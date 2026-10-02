"""Finite record traversal for attributed PE relocation and exception APIs.

Schemas and result objects remain pefile contracts (MIT, see ORIGIN.md).
This implementation treats declared directory/payload ends separately from
available file bytes. A malformed record stops that traversal with a warning;
a cumulative budget failure raises LimitError and never implies completeness.
"""
import struct

from . import api_contract
from .bounded_io import quarry_LimitError


def unpack_unwind(info, data, unpack_header):
    """Retain the staged API, checking operand slots before initialization.

    The attributed opcode classes and legacy optional-field representation are
    retained. In particular, this is not a new x64/IA64 loader implementation.
    """
    from . import image_reader as schema
    if info._finished_unpacking:
        return None
    unpack_header(data)
    code_end = 4 + info.CountOfCodes * 2
    handler_offset = 4 + ((info.CountOfCodes + 1) & ~1) * 2
    info._full_size = handler_offset + (4 if info.Flags else 0)
    if len(data) < info._full_size:
        return None  # first staged call establishes the required size
    if info.Version not in (1, 2):
        return 'Unsupported version of UNWIND_INFO at ' + hex(info.__file_offset__)
    info.UnwindCodes = []
    position = 4
    remaining = info.CountOfCodes
    while remaining:
        info._code_info.__unpack__(data[position:position + 2])
        operation = api_contract.attributes(schema.quarry_PrologEpilogOpsFactory)['create'](info._code_info)
        if operation is None:
            return 'Unknown UNWIND_CODE at ' + hex(info.__file_offset__ + position)
        operation_api = api_contract.attributes(operation)
        slots = operation_api['length_in_code_structures'](info._code_info, info)
        if type(slots) is not int or not 0 < slots <= remaining or position + 2 * slots > code_end:
            return 'UNWIND_CODE exceeds declared code slots at ' + hex(info.__file_offset__ + position)
        operation_api['initialize'](info._code_info, data[position:position + 2 * slots], info, info.__file_offset__ + position)
        info.UnwindCodes.append(operation)
        position += 2 * slots
        remaining -= slots
    info._opt_field_name = None
    if info.UNW_FLAG_EHANDLER or info.UNW_FLAG_UHANDLER:
        info._opt_field_name = 'ExceptionHandler'
    if info.UNW_FLAG_CHAININFO:
        info._opt_field_name = 'FunctionEntry'
    if info._opt_field_name is not None:
        api_contract.write_attribute(info, info._opt_field_name, struct.unpack('<I', data[handler_offset:handler_offset + 4])[0])
    info._finished_unpacking = True
    return None


class RecordReader:
    def __init__(self, pe):
        # Delayed import avoids a module initialization cycle with API bridges.
        from . import image_reader
        self.schema = image_reader
        self.pe = pe
        self.api = api_contract.attributes(pe)

    def warn(self, message):
        self.api['__warnings'].append(message)

    def span(self, rva, size, container=False):
        if type(rva) is not int or type(size) is not int or rva < 0 or size < 0:
            raise self.schema.quarry_PEFormatError('directory RVA/size must be nonnegative integers')
        if rva >= 1 << 32 or (not container and size > (1 << 32) - rva):
            raise self.schema.quarry_PEFormatError('directory span exceeds the 32-bit RVA space')
        return rva + size

    def tick(self, count=1):
        self.pe._quarry_directory_count += count
        if self.pe._quarry_directory_count > self.pe._quarry_directory_limit:
            raise quarry_LimitError('directory record budget exceeded')

    def width(self, fmt, bitfields=False):
        factory = self.schema.quarry_StructureWithBitfields if bitfields else self.schema.quarry_Structure
        width = api_contract.attributes(factory(fmt))['sizeof']()
        if width <= 0:
            raise self.schema.quarry_PEFormatError('empty directory record format')
        return width

    def data(self, rva, size, end=None):
        finish = self.span(rva, size)
        if end is not None and finish > end:
            raise self.schema.quarry_PEFormatError('record exceeds its declared container')
        data = self.api['get_data'](rva, size)
        if len(data) != size:
            raise self.schema.quarry_PEFormatError('directory record is truncated')
        return data

    def record(self, rva, fmt, end=None, partial_header=False):
        self.tick()
        width = self.width(fmt)
        if partial_header:
            if self.span(rva, width) > end:
                raise self.schema.quarry_PEFormatError('record exceeds its declared container')
            # Preserve the public corrupt-header diagnostic for short file data.
            data = self.api['get_data'](rva, width)
        else:
            data = self.data(rva, width, end)
        return self.pe.__unpack_data__(fmt, data, self.api['get_offset_from_rva'](rva))

    def base_relocations(self, rva, size, fmt=None):
        # Oversized directory declarations remain inspectable as partial input;
        # each actual read is checked in 32-bit RVA space and never wraps.
        end = self.span(rva, size, container=True)
        blocks = []
        header_fmt = self.pe.__IMAGE_BASE_RELOCATION_format__
        width = self.width(header_fmt)
        while rva < end:
            try:
                block = self.record(rva, header_fmt, end, partial_header=True)
            except self.schema.quarry_PEFormatError:
                self.warn(f"Invalid relocation information. Can't read data at RVA: {rva:#x}")
                break
            if block is None:
                break
            image_size = self.api['OPTIONAL_HEADER'].SizeOfImage
            if block.VirtualAddress > image_size:
                self.warn(f'Invalid relocation information. VirtualAddress outside of Image: {block.VirtualAddress:#x}')
                break
            if block.SizeOfBlock > image_size:
                self.warn(f'Invalid relocation information. SizeOfBlock too large: {block.SizeOfBlock}')
                break
            if block.SizeOfBlock == 0:
                # Retain the public terminal-padding record convention.
                blocks.append(self.schema.quarry_BaseRelocationData(struct=block, entries=[]))
                break
            if block.SizeOfBlock < width or block.SizeOfBlock > end - rva:
                self.warn(f'Invalid relocation block extent at RVA: {rva:#x}')
                break
            entry_width = self.width(fmt, True) if fmt is not None else 2
            if (block.SizeOfBlock - width) % entry_width:
                self.warn(f'Invalid relocation block alignment at RVA: {rva:#x}')
                break
            payload = rva + width
            entries = self.api['parse_relocations'](payload, block.VirtualAddress, block.SizeOfBlock - width) if fmt is None else self.api['parse_relocations_with_format'](payload, block.VirtualAddress, block.SizeOfBlock - width, fmt)
            blocks.append(self.schema.quarry_BaseRelocationData(struct=block, entries=entries))
            rva += block.SizeOfBlock  # validated >= header width; always advances
        return blocks

    def relocation_entries(self, data_rva, base_rva, size, fmt=None):
        self.span(data_rva, size)
        self.span(base_rva, 0)
        try:
            # Complete records preceding a short tail remain useful evidence.
            data = self.api['get_data'](data_rva, size)
            offset = self.api['get_offset_from_rva'](data_rva)
        except self.schema.quarry_PEFormatError:
            self.warn(f'Bad RVA in relocation data: {data_rva:#x}')
            return []
        bitfields = fmt is not None
        fmt = fmt if bitfields else self.pe.__IMAGE_BASE_RELOCATION_ENTRY_format__
        width = self.width(fmt, bitfields)
        if len(data) % width:
            self.warn(f'Incomplete relocation entry at RVA: {data_rva:#x}')
        entries, seen = [], set()
        unpack = self.pe.__unpack_data_with_bitfields__ if bitfields else self.pe.__unpack_data__
        for position in range(0, len(data) - len(data) % width, width):
            self.tick()
            entry = unpack(fmt, data[position:position + width], offset + position)
            if entry is None:
                break
            relative = entry.PageRelativeOffset if bitfields else entry.Data & 0xfff
            kind = None if bitfields else entry.Data >> 12
            key = relative if bitfields else (relative, kind)
            if key in seen:
                self.warn('Overlapping offsets in relocation data at RVA: 0x%x' % (relative + base_rva))
                return entries
            seen.add(key)
            values = dict(struct=entry, base_rva=base_rva, rva=base_rva + relative)
            if not bitfields:
                values['type'] = kind
            entries.append(self.schema.quarry_RelocationData(**values))
        if len(data) != size:
            self.warn(f'Truncated relocation data at RVA: {data_rva:#x}')
        return entries

    def dynamic_relocations(self, offset, section_number):
        self.span(offset, 0)
        if type(section_number) is not int or section_number < 0:
            raise self.schema.quarry_PEFormatError('dynamic relocation section must be a nonnegative integer')
        if not offset or not section_number or section_number > len(self.api['sections']):
            return None
        section = self.api['sections'][section_number - 1]
        rva = section.VirtualAddress + offset
        header_fmt = self.pe.__IMAGE_DYNAMIC_RELOCATION_TABLE_format__
        try:
            section_end = self.span(section.VirtualAddress, section.SizeOfRawData)
            header = self.record(rva, header_fmt, section_end)
        except self.schema.quarry_PEFormatError as error:
            self.warn(f"Invalid IMAGE_DYNAMIC_RELOCATION_TABLE information. Can't read data at RVA: {rva:#x}: {error}")
            return None
        if header is None:
            return None
        if header.Version != 1:
            self.warn(f'No parsing available for IMAGE_DYNAMIC_RELOCATION_TABLE.Version = {header.Version}')
            return None
        rva += self.width(header_fmt)
        try:
            end = self.span(rva, header.Size)
            if end > section_end:
                raise self.schema.quarry_PEFormatError('dynamic table exceeds selected section raw extent')
        except self.schema.quarry_PEFormatError as error:
            self.warn(f'Invalid IMAGE_DYNAMIC_RELOCATION_TABLE extent at RVA: {rva:#x}: {error}')
            return []
        results = []
        fmt = self.pe.__IMAGE_DYNAMIC_RELOCATION64_format__ if self.api['PE_TYPE'] == self.schema.quarry_OPTIONAL_HEADER_MAGIC_PE_PLUS else self.pe.__IMAGE_DYNAMIC_RELOCATION_format__
        width = self.width(fmt)
        while rva < end:
            try:
                record = self.record(rva, fmt, end)
                if record is None:
                    break
                payload = rva + width
                payload_end = self.span(payload, record.BaseRelocSize)
                if payload_end > end:
                    raise self.schema.quarry_PEFormatError('dynamic payload exceeds table')
            except self.schema.quarry_PEFormatError as error:
                self.warn(f"Invalid relocation information. Can't read data at RVA: {rva:#x}: {error}")
                break
            symbol = record.Symbol
            if symbol == 7:
                functions, bdd = self.function_overrides(payload, payload_end)
                results.append(self.schema.quarry_FunctionOverrideData(struct=record, symbol=symbol, bdd_relocs=bdd, func_relocs=functions))
            elif symbol >= 3:
                relocation_fmt = self.api['dynamic_relocation_format_by_symbol'].get(symbol) if symbol <= 5 else None
                relocations = self.api['parse_image_base_relocation_list'](payload, record.BaseRelocSize, relocation_fmt)
                results.append(self.schema.quarry_DynamicRelocationData(struct=record, symbol=symbol, relocations=relocations))
            rva = payload_end  # even an empty payload advances by its header
        return results

    def function_overrides(self, rva, end=None):
        self.span(rva, 0)
        functions, bdd = [], []
        try:
            fmt = self.pe.__IMAGE_FUNCTION_OVERRIDE_HEADER_format__
            header = self.record(rva, fmt, end)
            if header is None:
                return functions, bdd
            rva += self.width(fmt)
            function_end = self.span(rva, header.FuncOverrideSize)
            if end is not None and function_end > end:
                raise self.schema.quarry_PEFormatError('function records exceed dynamic payload')
            fmt = self.pe.__IMAGE_FUNCTION_OVERRIDE_DYNAMIC_RELOCATION_format__
            width = self.width(fmt)
            while rva < function_end:
                record = self.record(rva, fmt, function_end)
                if record is None:
                    return functions, bdd
                payload = rva + width
                relocation_rva = self.span(payload, record.RvaSize)
                next_rva = self.span(relocation_rva, record.BaseRelocSize)
                if record.RvaSize % 4 or next_rva > function_end:
                    raise self.schema.quarry_PEFormatError('invalid function override payload extent/alignment')
                # Read integers separately: no allocation based on declared size.
                overrides = []
                for position in range(payload, relocation_rva, 4):
                    self.tick()
                    overrides.append(struct.unpack('<I', self.data(position, 4, function_end))[0])
                relocations = self.api['parse_image_base_relocation_list'](relocation_rva, record.BaseRelocSize)
                functions.append(self.schema.quarry_FunctionOverrideDynamicRelocationData(struct=record, func_rva=record.OriginalRva, override_rvas=overrides, relocations=relocations))
                rva = next_rva
            fmt = self.pe.__IMAGE_BDD_INFO_format__
            info = self.record(rva, fmt, end)
            if info is None:
                return functions, bdd
            rva += self.width(fmt)
            bdd_end = self.span(rva, info.BDDSize)
            if info.BDDSize % 8 or (end is not None and bdd_end > end):
                raise self.schema.quarry_PEFormatError('invalid BDD payload extent/alignment')
            fmt = self.pe.__IMAGE_BDD_DYNAMIC_RELOCATION_format__
            width = self.width(fmt)
            while rva < bdd_end:
                entry = self.record(rva, fmt, bdd_end)
                if entry is None:
                    break
                bdd.append(self.schema.quarry_BddDynamicRelocationData(struct=entry))
                rva += width
        except self.schema.quarry_PEFormatError as error:
            self.warn(f'Invalid function override data at RVA: {rva:#x}: {error}')
        return functions, bdd

    def exceptions(self, rva, size):
        if self.api['FILE_HEADER'].Machine not in (0x8664, 0x200):
            return None
        end = self.span(rva, size)
        functions, by_begin, unwind_cache = [], {}, {}
        fmt = self.pe.__RUNTIME_FUNCTION_format__
        width = self.width(fmt)
        while rva + width <= end:
            try:
                runtime = self.record(rva, fmt, end)
                if runtime is None:
                    break
                unwind = None
                if not runtime.UnwindData & 1:
                    if runtime.UnwindData in unwind_cache:
                        unwind = unwind_cache[runtime.UnwindData]
                    else:
                        self.tick()
                        unwind = self.schema.quarry_UnwindInfo(file_offset=self.api['get_offset_from_rva'](runtime.UnwindData))
                        unwind_api = api_contract.attributes(unwind)
                        for stage in range(2):
                            warning = unwind_api['unpack_in_stages'](self.data(runtime.UnwindData, unwind_api['sizeof']()))
                            if warning is not None:
                                raise self.schema.quarry_PEFormatError(warning)
                            if stage == 0:
                                # Include operand slots before decoding their operations.
                                self.tick(unwind.CountOfCodes)
                        if not unwind._finished_unpacking:
                            raise self.schema.quarry_PEFormatError('incomplete UNWIND_INFO')
                        unwind_cache[runtime.UnwindData] = unwind
                        self.pe.__structures__.append(unwind)
                entry = self.schema.quarry_ExceptionsDirEntryData(struct=runtime, unwindinfo=unwind)
                functions.append(entry)
                by_begin[runtime.BeginAddress] = entry
            except self.schema.quarry_PEFormatError as error:
                self.warn(f'Invalid exception information at RVA: {rva:#x}: {error}')
                break
            rva += width
        if rva < end and end - rva < width:
            self.warn(f'Incomplete runtime function record at RVA: {rva:#x}')
        for entry in functions:
            unwind = entry.unwindinfo
            if unwind is None or not api_contract.has_attribute(unwind, 'FunctionEntry'):
                continue
            offset = api_contract.attributes(api_contract.attributes(entry)['struct'])['get_file_offset']()
            if unwind.FunctionEntry not in by_begin:
                self.warn(f'FunctionEntry of UNWIND_INFO at {offset:x} points to an entry that does not exist')
                continue
            try:
                api_contract.attributes(unwind)['set_chained_function_entry'](by_begin[unwind.FunctionEntry])
            except self.schema.quarry_PEFormatError as error:
                self.warn(f'Failed parsing FunctionEntry of UNWIND_INFO at {offset:x}: {error}')
        return functions
