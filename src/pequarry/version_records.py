"""Parent-contained PE version blocks with finite UTF-16 processing.

Windows schemas and public result objects remain attributed pefile contracts.
See ORIGIN.md. Lengths are checked in bytes; String.ValueLength is in UTF-16
units, while fixed values and Var translations declare byte lengths.
"""
import struct

from . import api_contract
from .directory_records import RecordReader


class VersionReader(RecordReader):
    def __init__(self, pe, resource):
        super().__init__(pe)
        self.resource = resource
        self.start = self.api['get_offset_from_rva'](resource.OffsetToData)
        self.span(resource.OffsetToData, resource.Size)
        if type(self.start) is not int or not 0 <= self.start <= len(pe.__data__):
            raise self.schema.quarry_PEFormatError('version resource offset is outside the file')
        self.end = min(self.start + resource.Size, len(pe.__data__))

    def read(self, offset, size, end):
        if offset < self.start or size < 0 or offset + size > end or end > self.end:
            raise self.schema.quarry_PEFormatError('version field exceeds its parent block')
        return self.pe.__data__[offset:offset + size]

    def align(self, offset):
        return offset + ((-(self.resource.OffsetToData + offset - self.start)) & 3)

    def text(self, offset, end, units=None, ascii_key=False):
        if units == 0:
            return b'', offset
        limit = end if units is None else min(end, offset + 2 * units)
        parts = []
        while offset + 2 <= limit:
            size = min(256, limit - offset) & ~1
            data = self.read(offset, size, end)
            stop = None
            for position in range(0, len(data), 2):
                if data[position:position + 2] == b'\0\0':
                    stop = position
                    break
            consumed = len(data) if stop is None else stop + 2
            self.tick(consumed // 2)
            parts.append(data if stop is None else data[:stop])
            offset += consumed
            if stop is not None:
                value = b''.join(parts).decode('utf-16le', 'backslashreplace')
                return value.encode('ascii' if ascii_key else 'utf-8', 'backslashreplace_'), offset
        if units is None:
            raise self.schema.quarry_PEFormatError('unterminated version key inside its parent')
        value = b''.join(parts).decode('utf-16le', 'backslashreplace')
        return value.encode('utf-8', 'backslashreplace_'), offset

    def block(self, offset, parent_end, fmt):
        self.tick()
        width = self.width(fmt)
        value = self.pe.__unpack_data__(fmt, self.read(offset, width, parent_end), offset)
        if value is None:
            raise self.schema.quarry_PEFormatError('invalid version block header')
        if value.Length < width or offset + value.Length > parent_end:
            raise self.schema.quarry_PEFormatError('version block extent exceeds its parent or does not advance')
        end = offset + value.Length
        key, after_key = self.text(offset + width, end)
        return value, key, self.align(after_key), end

    def strings(self, info, offset, end):
        info.StringTable = []
        while offset < end:
            table, key, entries_start, table_end = self.block(offset, end, self.pe.__StringTable_format__)
            table.LangID = key
            table.entries, table.entries_offsets, table.entries_lengths = {}, {}, {}
            table._quarry_value_capacities = {}
            info.StringTable.append(table)
            position = entries_start
            while position < table_end:
                entry, key, value_offset, entry_end = self.block(position, table_end, self.pe.__String_format__)
                if entry.ValueLength and entry.ValueLength * 2 > entry_end - value_offset:
                    raise self.schema.quarry_PEFormatError('version String.ValueLength exceeds its String block')
                value, _ = self.text(value_offset, entry_end, entry.ValueLength)
                # Preserve legacy UTF-8 byte lengths; separate actual UTF-16
                # capacity prevents edits from touching adjacent blocks.
                table.entries[key] = value
                table.entries_offsets[key] = (position + 6, value_offset)
                table.entries_lengths[key] = (len(key), len(value))
                table._quarry_value_capacities[key] = min(entry.ValueLength, len(value.decode('utf-8').encode('utf-16le')) // 2)
                position = self.align(entry_end)
            offset = self.align(table_end)

    def variables(self, info, offset, end):
        info.name = 'VarFileInfo'
        info.Var = []
        while offset < end:
            value, key, data_offset, value_end = self.block(offset, end, self.pe.__Var_format__)
            if value.ValueLength % 4 or value.ValueLength > value_end - data_offset:
                raise self.schema.quarry_PEFormatError('version Var translation extent/alignment is invalid')
            value.translations = []
            for position in range(data_offset, data_offset + value.ValueLength, 4):
                self.tick()
                language, codepage = struct.unpack('<HH', self.read(position, 4, value_end))
                value.translations.append((language, codepage))
                # Preserve the existing last-pair dictionary result.
                value.entry = {key: f'0x{language:04x} 0x{codepage:04x}'}
            info.Var.append(value)
            offset = self.align(value_end)

    def parse(self):
        info = None
        try:
            info, key, fixed_offset, end = self.block(self.start, self.end, self.pe.__VS_VERSIONINFO_format__)
            if key != b'VS_VERSION_INFO':
                self.warn('Invalid VS_VERSION_INFO block: ' + key.decode('utf-8', 'backslashreplace')[:128].replace('\0', '\\00'))
                return
            info.Key = key
            info.metadata_complete = False
            if not api_contract.has_attribute(self.pe, 'VS_VERSIONINFO'):
                self.api['VS_VERSIONINFO'] = []
            self.api['VS_VERSIONINFO'].append(info)
            if info.ValueLength:
                fixed_width = self.width(self.pe.__VS_FIXEDFILEINFO_format__)
                if info.ValueLength < fixed_width:
                    raise self.schema.quarry_PEFormatError('fixed version value is shorter than VS_FIXEDFILEINFO')
                self.read(fixed_offset, info.ValueLength, end)
                self.tick()
                fixed = self.pe.__unpack_data__(self.pe.__VS_FIXEDFILEINFO_format__, self.read(fixed_offset, fixed_width, end), fixed_offset)
                if fixed is None:
                    return
                if not api_contract.has_attribute(self.pe, 'VS_FIXEDFILEINFO'):
                    self.api['VS_FIXEDFILEINFO'] = []
                self.api['VS_FIXEDFILEINFO'].append(fixed)
            position = self.align(fixed_offset + info.ValueLength)
            if not api_contract.has_attribute(self.pe, 'FileInfo'):
                self.api['FileInfo'] = []
            group = []
            if position < end:
                self.api['FileInfo'].append(group)
            while position < end:
                child, key, child_start, child_end = self.block(position, end, self.pe.__StringFileInfo_format__)
                child.Key = key
                group.append(child)
                if key.startswith(b'StringFileInfo') and child.Type in (0, 1) and child.ValueLength == 0:
                    self.strings(child, child_start, child_end)
                elif key.startswith(b'VarFileInfo') and child.Type in (0, 1) and child.ValueLength == 0:
                    self.variables(child, child_start, child_end)
                position = self.align(child_end)
            info.metadata_complete = True
        except self.schema.quarry_PEFormatError as error:
            self.warn(f'Invalid version information at file offset {self.start:#x}: {error}')


def parse_version(pe, resource):
    from . import image_reader
    try:
        parser = VersionReader(pe, resource)
    except image_reader.quarry_PEFormatError:
        api_contract.attributes(pe)['__warnings'].append(f'Error parsing the version information, attempting to read OffsetToData with RVA: {resource.OffsetToData:#x}')
        return
    parser.parse()
