"""Normal resource/version comparison corpus; field edge fixes have own tests."""
import hashlib
import importlib
import json
import struct
import sys
from resource_fixtures import BASE, make_image, tree_payload, version_payload

module = importlib.import_module(sys.argv[1])
results = []


def tree(node):
    value = {'header': node.struct.__pack__().hex(), 'offset': node.struct.get_file_offset(), 'entries': []}
    if hasattr(node, 'strings'):
        value['strings'] = node.strings
    for entry in node.entries:
        child = {'header': entry.struct.__pack__().hex(), 'offset': entry.struct.get_file_offset(), 'id': entry.id, 'name': str(entry.name) if entry.name is not None else None}
        if hasattr(entry, 'directory'):
            child['directory'] = tree(entry.directory)
        else:
            child['data'] = {'header': entry.data.struct.__pack__().hex(), 'offset': entry.data.struct.get_file_offset(), 'lang': entry.data.lang, 'sublang': entry.data.sublang}
        value['entries'].append(child)
    return value


for name in (None, 'owned', '中文', '😀'):
    for kind in (10, 6):
        for count in range(1, 9):
            data = b''.join(struct.pack('<H', len(value)) + value.encode('utf-16le') for value in ['word-'+str(i) for i in range(count)])
            payload = bytearray(tree_payload(kind, data if kind == 6 else None, name))
            if name is not None:
                offset = struct.unpack_from('<I', payload, 16)[0] & 0x7fffffff
                struct.pack_into('<H', payload, offset, len(name.encode('utf-16le'))//2)
            pe, raw = make_image(module, payload)
            root = pe.parse_resources_directory(BASE, len(payload))
            results.append({'case': f'resource-{name}-{kind}-{count}', 'tree': tree(root), 'warnings': pe.get_warnings(), 'serialized': hashlib.sha256(pe.write()).hexdigest(), 'input_unchanged': bytes(pe.__data__) == raw})
for count in range(1, 17):
    for content in ('owned', 'é', '中文', '😀'):
        from types import SimpleNamespace
        payload = version_payload(entries=[('key'+str(i), content+str(i)) for i in range(count)])
        pe, raw = make_image(module, payload)
        pe.parse_version_information(SimpleNamespace(OffsetToData=BASE, Size=len(payload)))
        group = []
        for info in pe.FileInfo[0]:
            item = {'header': info.__pack__().hex(), 'offset': info.get_file_offset(), 'key': info.Key.hex()}
            if hasattr(info, 'StringTable'):
                item['tables'] = [{'header': table.__pack__().hex(), 'offset': table.get_file_offset(), 'language': table.LangID.hex(), 'entries': {key.hex():value.hex() for key,value in table.entries.items()}, 'offsets': {key.hex():value for key,value in table.entries_offsets.items()}, 'lengths': {key.hex():value for key,value in table.entries_lengths.items()}} for table in info.StringTable]
            else:
                item['variables'] = [{'header': value.__pack__().hex(), 'offset': value.get_file_offset(), 'entry': {key.hex():text for key,text in value.entry.items()}} for value in info.Var]
            group.append(item)
        results.append({'case': f'version-{count}-{content}', 'fixed': [item.__pack__().hex() for item in pe.VS_FIXEDFILEINFO], 'groups': group, 'warnings': pe.get_warnings(), 'serialized': hashlib.sha256(pe.write()).hexdigest(), 'input_unchanged': bytes(pe.__data__) == raw})
print(json.dumps(results, sort_keys=True))
