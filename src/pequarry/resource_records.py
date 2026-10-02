"""Finite static resource traversal; schemas/result classes remain attributed.

See ORIGIN.md for pefile MIT provenance. A zero directory size means unknown
metadata span, not unlimited work. Explicit stacks avoid interpreter recursion;
all records and consumed UTF-16 units share the cumulative directory budget.
"""
from dataclasses import dataclass, field
from bisect import bisect_left
import struct

from . import api_contract
from .bounded_io import quarry_INPUT_LIMIT, quarry_in_memory_bytes
from .directory_records import RecordReader


def parse_strings(data, counter, output, tick=None):
    """Read unsigned-length UTF-16 cells; report an incomplete decode.

    A decodable short final value remains useful static evidence and retains the
    legacy dictionary result. It is sliced only from actual bytes and flagged.
    """
    data = quarry_in_memory_bytes(data, quarry_INPUT_LIMIT)
    if type(counter) is not int:
        raise ValueError('resource string counter must be an integer')
    position = errors = 0
    incomplete = False
    while position + 2 <= len(data):
        length = struct.unpack_from('<H', data, position)[0]
        position += 2
        incomplete |= length * 2 > len(data) - position
        if tick is not None:
            tick(1 + length)
        if length:
            try:
                output[counter] = data[position:position + 2 * length].decode('utf-16le')
            except UnicodeDecodeError:
                errors += 1
                incomplete = True
                if errors >= 3:
                    break
        position += 2 * length
        counter += 1
    return incomplete or position < len(data)


@dataclass
class Frame:
    header: object
    rva: int
    level: int
    directory_rva: int
    count: int
    position: int = 0
    entries: list = field(default_factory=list)
    name_spans: list = field(default_factory=list)
    pending: tuple | None = None
    incomplete: bool = False


class ResourceReader(RecordReader):
    def read_record(self, rva, fmt, end=None):
        self.tick()
        width = self.width(fmt)
        finish = self.span(rva, width)
        if end is not None and finish > end:
            raise self.schema.quarry_PEFormatError('resource metadata exceeds declared directory')
        return self.pe.__unpack_data__(fmt, self.api['get_data'](rva, width), self.api['get_offset_from_rva'](rva))

    def entry(self, rva, end=None):
        try:
            result = self.read_record(rva, self.pe.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__, end)
        except self.schema.quarry_PEFormatError:
            return None
        if result is not None:
            result.NameOffset = result.Name & 0x7fffffff
            result.NameIsString = result.Name >> 31
            result.Id = result.Name & 0xffff
            result.OffsetToDirectory = result.OffsetToData & 0x7fffffff
            result.DataIsDirectory = result.OffsetToData >> 31
        return result

    def data_entry(self, rva, end=None):
        try:
            return self.read_record(rva, self.pe.__IMAGE_RESOURCE_DATA_ENTRY_format__, end)
        except self.schema.quarry_PEFormatError:
            self.warn(f'Error parsing a resource directory data entry, the RVA is invalid: {rva:#x}')
            return None

    def open_frame(self, rva, level, end):
        if level > self.schema.quarry_MAX_RESOURCE_DEPTH:
            self.warn(f'Error parsing the resources directory. Excessively nested table depth {level} (>{self.schema.quarry_MAX_RESOURCE_DEPTH})')
            return None
        try:
            header = self.read_record(rva, self.pe.__IMAGE_RESOURCE_DIRECTORY_format__, end)
        except self.schema.quarry_PEFormatError:
            self.warn(f"Invalid resources directory. Can't read directory data at RVA: {rva:#x}")
            return None
        if header is None:
            self.warn(f"Invalid resources directory. Can't parse directory data at RVA: {rva:#x}")
            return None
        count = header.NumberOfNamedEntries + header.NumberOfIdEntries
        if count > 4096:
            self.warn(f'Error parsing the resources directory. The directory contains {count} entries (>4096)')
            return None
        self.api['__total_resource_entries_count'] += count
        if self.api['__total_resource_entries_count'] > self.schema.quarry_MAX_RESOURCE_ENTRIES:
            self.warn(f"Error parsing the resources directory. The file contains at least {self.api['__total_resource_entries_count']} entries (>{self.schema.quarry_MAX_RESOURCE_ENTRIES})")
            return None
        return Frame(header, rva + self.width(self.pe.__IMAGE_RESOURCE_DIRECTORY_format__), level, rva, count)

    def name(self, rva, frame, end):
        length_data = self.data(rva, 2, end)
        length = struct.unpack('<H', length_data)[0]
        finish = self.span(rva, 2 + length * 2)
        if end is not None and finish > end:
            raise self.schema.quarry_PEFormatError('resource name exceeds declared directory')
        self.tick(length)
        data = self.data(rva + 2, length * 2, end)
        # Exact shared references are permitted; partial name overlaps are not.
        self.tick(1 + len(frame.name_spans).bit_length())
        index = bisect_left(frame.name_spans, (rva, finish))
        shared = index < len(frame.name_spans) and frame.name_spans[index] == (rva, finish)
        overlaps = not shared and ((index > 0 and frame.name_spans[index - 1][1] > rva) or (index < len(frame.name_spans) and frame.name_spans[index][0] < finish))
        if overlaps:
            self.warn(f'Error parsing the resources directory, attempting to read entry name. Entry names overlap {rva:#x}')
            return None, True
        if not shared:
            frame.name_spans.insert(index, (rva, finish))
        name = self.schema.quarry_UnicodeStringWrapperPostProcessor(self.pe, rva)
        # Preserve the wrapper's public type, with an owned bounded byte result.
        encoded = data.decode('utf-16le', 'backslashreplace').split('\0', 1)[0].encode('utf-8', 'backslashreplace_')
        api_contract.attributes(name)['string'] = encoded
        self.api['__total_resource_bytes'] += length
        return name, False

    def append_child(self, frame, result, name, identity, child):
        if identity == self.schema.quarry_RESOURCE_TYPE['RT_STRING']:
            for resource_id in child.entries:
                if not api_contract.has_attribute(resource_id, 'directory'):
                    continue
                strings = {}
                complete = True
                for language in resource_id.directory.entries:
                    if language is None or not api_contract.has_attribute(language, 'data') or resource_id.id is None:
                        complete = False
                        continue
                    info = api_contract.attributes(language.data)['struct']
                    try:
                        self.span(info.OffsetToData, info.Size)
                        # Bound character processing before reading a declared span.
                        self.tick((info.Size + 1) // 2)
                        data = self.api['get_data'](info.OffsetToData, info.Size)
                        complete &= len(data) == info.Size
                    except self.schema.quarry_PEFormatError:
                        complete = False
                        self.warn(f'Error parsing resource of type RT_STRING at RVA {info.OffsetToData:#x} with size {info.Size}')
                        continue
                    complete &= not parse_strings(data, (int(resource_id.id) - 1) * 16, strings)
                resource_id.directory.strings = strings
                resource_id.directory.strings_complete = complete
        frame.entries.append(self.schema.quarry_ResourceDirEntryData(struct=result, name=name, id=identity, directory=child))
        frame.incomplete |= not child.metadata_complete
        if frame.level == 0 and result.Id == self.schema.quarry_RESOURCE_TYPE['RT_VERSION']:
            try:
                versions = child.entries[0].directory.entries
            except (AttributeError, IndexError):
                return
            for version in versions:
                if api_contract.has_attribute(version, 'data'):
                    self.api['parse_version_information'](api_contract.attributes(version.data)['struct'])

    def resources(self, rva, size=0, base_rva=None, level=0, dirs=None):
        self.span(rva, 0)
        if type(size) is not int or size < 0 or type(level) is not int or level < 0:
            raise self.schema.quarry_PEFormatError('resource size/level must be nonnegative integers')
        base_rva = rva if base_rva is None else base_rva
        self.span(base_rva, 0)
        end = self.span(base_rva, size, container=True) if size else None
        initial = frozenset([rva] if dirs is None else dirs)
        root = self.open_frame(rva, level, end)
        if root is None:
            return None
        stack = [root]
        active = {rva}
        while stack:
            frame = stack[-1]
            if frame.position >= frame.count:
                completed = self.schema.quarry_ResourceDirData(struct=frame.header, entries=frame.entries)
                completed.metadata_complete = not frame.incomplete
                stack.pop()
                active.remove(frame.directory_rva)
                if not stack:
                    return completed
                parent = stack[-1]
                result, name, identity = parent.pending
                parent.pending = None
                self.append_child(parent, result, name, identity, completed)
                continue
            if not self.api['__resource_size_limit_reached'] and self.api['__total_resource_bytes'] > self.api['__resource_size_limit_upperbounds']:
                self.api['__resource_size_limit_reached'] = True
                self.warn(f"Resource size {self.api['__total_resource_bytes']:#x} exceeds file size {self.api['__resource_size_limit_upperbounds']:#x}, overlapping resources found.")
            entry_rva = frame.rva + frame.position * 8
            result = self.entry(entry_rva, end)
            if result is None:
                self.warn(f'Error parsing the resources directory, Entry {frame.position} is invalid, RVA = {entry_rva:#x}. ')
                frame.incomplete = True
                frame.position = frame.count
                continue
            identity = None if result.NameIsString else result.Name
            name = None
            if result.NameIsString:
                name_rva = base_rva + result.NameOffset
                try:
                    name, overlaps = self.name(name_rva, frame, end)
                    if overlaps:
                        frame.incomplete = True
                        frame.position = frame.count
                        continue
                except self.schema.quarry_PEFormatError:
                    frame.incomplete = True
                    self.warn(f"Error parsing the resources directory, attempting to read entry name. Can't read unicode string at offset {name_rva:#x}")
            frame.position += 1
            target = base_rva + result.OffsetToDirectory
            if result.DataIsDirectory:
                if target in initial or target in active:
                    # Public partial-tree behavior: stop this frame at a cycle.
                    frame.incomplete = True
                    frame.position = frame.count
                    continue
                child = self.open_frame(target, frame.level + 1, end)
                if child is None:
                    frame.incomplete = True
                    frame.position = frame.count
                    continue
                frame.pending = (result, name, identity)
                stack.append(child)
                active.add(target)
            else:
                info = self.data_entry(target, end)
                if info is None:
                    frame.incomplete = True
                    frame.position = frame.count
                    continue
                self.api['__total_resource_bytes'] += info.Size
                data = self.schema.quarry_ResourceDataEntryData(struct=info, lang=result.Name & 0x3ff, sublang=result.Name >> 10)
                frame.entries.append(self.schema.quarry_ResourceDirEntryData(struct=result, name=name, id=identity, data=data))
        return None
