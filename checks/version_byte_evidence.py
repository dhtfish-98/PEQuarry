"""Independently decode one fixed version record as bounded raw byte fields.

No runtime parser APIs participate in decoding. Results are declarative offsets,
lengths, types, UTF-16 strings and raw little-endian DWORD/WORD values. Microsoft
VS_VERSIONINFO/String/Var layout links are recorded in the returned evidence.
"""
import struct
from types import SimpleNamespace

SPECIFICATIONS = [
    'https://learn.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo',
    'https://learn.microsoft.com/en-us/windows/win32/menurc/string-str',
    'https://learn.microsoft.com/en-us/windows/win32/menurc/var-str',
]


def decode(raw, start=600):
    def record(offset, parent_end):
        assert offset + 6 <= parent_end
        length, size, kind = struct.unpack_from('<HHH', raw, offset)
        assert length >= 6 and offset + length <= parent_end
        end = offset + length
        key_start = cursor = offset + 6
        while cursor + 2 <= end and raw[cursor:cursor+2] != b'\0\0':
            cursor += 2
        assert cursor + 2 <= end
        key = raw[key_start:cursor].decode('utf-16le')
        value_start = (cursor + 2 + 3) & ~3
        return {'offset':offset,'length':length,'value_length':size,'type':kind,'end':end,'key':key,'key_offset':key_start,'value_offset':value_start,'header_hex':raw[offset:offset+6].hex()}
    root = record(start, len(raw))
    assert root['key'] == 'VS_VERSION_INFO' and root['value_length'] == 52
    root['fixed_dwords'] = struct.unpack_from('<13I', raw, root['value_offset'])
    cursor = (root['value_offset'] + 52 + 3) & ~3
    groups = []
    while cursor < root['end']:
        child = record(cursor, root['end']);child['children']=[]
        position = child['value_offset']
        while position < child['end']:
            item = record(position, child['end']);item['children']=[]
            if child['key'] == 'StringFileInfo':
                entry_offset = item['value_offset']
                while entry_offset < item['end']:
                    entry = record(entry_offset, item['end'])
                    finish = entry['value_offset'] + entry['value_length'] * 2
                    assert not entry['value_length'] or finish <= entry['end']
                    value = raw[entry['value_offset']:finish].decode('utf-16le').split('\0',1)[0]
                    entry['value'] = value
                    item['children'].append(entry)
                    entry_offset = (entry['end'] + 3) & ~3
            else:
                assert child['key'] == 'VarFileInfo'
                finish = item['value_offset'] + item['value_length']
                assert item['value_length'] % 4 == 0 and finish <= item['end']
                item['translations'] = [struct.unpack_from('<HH', raw, offset) for offset in range(item['value_offset'], finish, 4)]
            child['children'].append(item)
            position = (item['end'] + 3) & ~3
        groups.append(child)
        cursor = (child['end'] + 3) & ~3
    return {'root':root,'groups':groups,'specifications':SPECIFICATIONS}


def expected_file_info(source, pe, evidence, raw):
    """Feed independent decoded records to the unchanged source formatter."""
    def structure(record, fmt):
        value = source.Structure(fmt, file_offset=record['offset'])
        value.__unpack__(raw[record['offset']:record['offset']+6])
        return value
    group = []
    for record in evidence['groups']:
        info = structure(record, pe.__StringFileInfo_format__)
        info.Key = record['key'].encode()
        if record['key'] == 'StringFileInfo':
            info.StringTable = []
            for table_record in record['children']:
                table = structure(table_record, pe.__StringTable_format__)
                table.LangID = table_record['key'].encode()
                table.entries, table.entries_offsets, table.entries_lengths = {}, {}, {}
                for entry in table_record['children']:
                    key, value = entry['key'].encode(), entry['value'].encode()
                    table.entries[key] = value
                    table.entries_offsets[key] = (entry['key_offset'], entry['value_offset'])
                    table.entries_lengths[key] = (len(key), len(value))
                info.StringTable.append(table)
        else:
            info.name = 'VarFileInfo'
            info.Var = []
            for var_record in record['children']:
                var = structure(var_record, pe.__Var_format__)
                for language, codepage in var_record['translations']:
                    var.entry = {var_record['key'].encode():f'0x{language:04x} 0x{codepage:04x}'}
                info.Var.append(var)
        group.append(info)
    return [group] if group else []
