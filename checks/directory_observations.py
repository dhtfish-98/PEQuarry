"""Repeat synthetic normal directory observations against both implementations."""
import hashlib
import importlib
import json
import random
import struct
import sys
from directory_fixtures import image, relocation_payload, override_payload, dynamic_payload, exception_payload, normalize_blocks

module = importlib.import_module(sys.argv[1])
cases = []
rng = random.Random(174001)
for index in range(128):
    entries = tuple((rng.randrange(16) << 12) | value for value in rng.sample(range(0x10, 0x100), 2 * rng.randrange(1, 9)))
    payload = relocation_payload(entries=entries)
    pe, rva, raw = image(module, payload, bool(index % 2))
    blocks = pe.parse_image_base_relocation_list(rva, len(payload))
    cases.append({'case': 'base-' + str(index), 'blocks': normalize_blocks(blocks), 'serialized': hashlib.sha256(pe.write()).hexdigest(), 'raw_unchanged': bytes(pe.__data__) == raw, 'warnings': pe.get_warnings()})
for is64 in (False, True):
    for symbol in (0, 3, 4, 5, 6, 7):
        inner = override_payload() if symbol == 7 else relocation_payload(entries=(0x3010, 0x3012))
        if symbol == 3:
            inner = struct.pack('<IIII', 0x200, 16, 0x12345010, 0x12345012)
        pe, rva, raw = image(module, dynamic_payload(is64, symbol, inner), is64)
        results = pe.parse_dynamic_relocations(rva - pe.sections[0].VirtualAddress, 1)
        observations = []
        for result in results:
            item = {'symbol': result.symbol, 'header': result.struct.__pack__().hex()}
            if symbol == 7:
                item['functions'] = [{'header': entry.struct.__pack__().hex(), 'rvas': entry.override_rvas, 'relocations': normalize_blocks(entry.relocations)} for entry in result.func_relocs]
                item['bdd'] = [entry.struct.__pack__().hex() for entry in result.bdd_relocs]
            else:
                item['relocations'] = normalize_blocks(result.relocations)
            observations.append(item)
        cases.append({'case': f'dynamic-{is64}-{symbol}', 'results': observations, 'serialized': hashlib.sha256(pe.write()).hexdigest(), 'raw_unchanged': bytes(pe.__data__) == raw, 'warnings': pe.get_warnings()})
for count in (1, 2, 5):
    for unwind in (b'\x01\0\0\0', b'\x01\x02\x01\0\x01\x30\0\0', b'\x09\0\0\0' + struct.pack('<I', 0x210)):
        pe, rva, raw = image(module, exception_payload(unwind, count), True)
        results = pe.parse_exceptions_directory(rva, count * 12)
        cases.append({'case': f'exceptions-{count}-{unwind.hex()}', 'results': [{'header': entry.struct.__pack__().hex(), 'unwind': bytes(entry.unwindinfo.__pack__()).hex(), 'dump': entry.unwindinfo.dump(), 'dictionary': entry.unwindinfo.dump_dict()} for entry in results], 'serialized': hashlib.sha256(pe.write()).hexdigest(), 'raw_unchanged': bytes(pe.__data__) == raw, 'warnings': pe.get_warnings()})
print(json.dumps(cases, sort_keys=True))
