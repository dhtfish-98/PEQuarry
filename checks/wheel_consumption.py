"""Check wheel-installed source identity and representative offline operations."""
from pathlib import Path as ConsumptionPath
import hashlib as consumption_hashlib
import importlib as consumption_importlib
import json as consumption_json
import subprocess as consumption_subprocess
import sys as consumption_sys

consumption_root = ConsumptionPath(consumption_sys.argv[1]).resolve()
consumption_name = consumption_sys.argv[2]
consumption_package = consumption_name.lower()
consumption_module = consumption_importlib.import_module(consumption_package)
consumption_location = ConsumptionPath(consumption_module.__file__).resolve()
assert 'site-packages' in str(consumption_location), str(consumption_location)
consumption_file_count = 0
for consumption_file in (consumption_root / 'src' / consumption_package).rglob('*.py'):
    consumption_relative = consumption_file.relative_to(consumption_root / 'src' / consumption_package)
    consumption_installed = consumption_location.parent / consumption_relative
    assert consumption_installed.read_bytes() == consumption_file.read_bytes(), str(consumption_relative)
    assert bool(consumption_installed.stat().st_mode & 0o111) == bool(consumption_file.stat().st_mode & 0o111), str(consumption_relative)+' executable mode differs'
    consumption_file_count += 1
consumption_cases = []
if consumption_name == 'GadgetHarbor':
    consumption_command = ConsumptionPath(consumption_sys.executable).with_name('GadgetHarbor')
    consumption_help = consumption_subprocess.run([str(consumption_command), '--help'], capture_output=True, check=True, text=True)
    assert '--binary' in consumption_help.stdout and '--depth' in consumption_help.stdout
    consumption_cases.append('installed console help')
    consumption_output = consumption_subprocess.run([str(consumption_command), '--binary', str(consumption_root/'fixtures/raw-x86.raw'), '--rawArch', 'x86', '--rawMode', '32', '--depth', '5'], capture_output=True, check=True, text=True).stdout
    assert consumption_output == 'Gadgets information\n============================================================\n0x0000000e : mov dword ptr [ecx], eax ; xor eax, eax ; ret\n0x00000012 : ret\n0x00000010 : xor eax, eax ; ret\n\nUnique gadgets found: 3\n'
    consumption_cases.append('installed raw-image static disassembly')
elif consumption_name == 'PEQuarry':
    # The original export fixture is source-embedded; only its static bytes are used.
    import importlib.util as consumption_util
    consumption_spec = consumption_util.spec_from_file_location('embedded_export_fixtures', consumption_root/'checks/test_quarry_export_test.py')
    consumption_fixture = consumption_util.module_from_spec(consumption_spec)
    consumption_spec.loader.exec_module(consumption_fixture)
    consumption_reader = consumption_importlib.import_module('pequarry.image_reader')
    for consumption_index, consumption_initial in enumerate((consumption_fixture.quarry_PE_32, consumption_fixture.quarry_PE_64)):
        consumption_raw = bytearray(consumption_initial)
        for consumption_export in range(29):
            consumption_raw[(536 if consumption_index == 0 else 552) + 4 * consumption_export] = 1
        consumption_image = consumption_reader.quarry_PE(data=bytes(consumption_raw))
        assert consumption_image.FILE_HEADER.Machine in (0x14c, 0x8664)
        assert len(consumption_image.DIRECTORY_ENTRY_EXPORT.symbols) == 29
        assert consumption_image.quarry_write() == bytes(consumption_raw)
        assert consumption_image.quarry_generate_checksum() > 0
        consumption_image.quarry_close()
        consumption_cases.append('installed PE32/64 parse, export table, write bytes and checksum')
    consumption_signatures = consumption_importlib.import_module('pequarry.signature_tools')
    consumption_bounds = consumption_importlib.import_module('pequarry.bounded_io')
    consumption_db = consumption_signatures.SignatureDatabase(data='[owned]\nsignature = 41 ??\nep_only = true\n')
    assert consumption_db.match_data(b'AB') == (0, [['owned']])
    assert consumption_db.match_data(b'A') == []
    consumption_cases.append('installed full-length terminal wildcard')
    try:
        consumption_reader.PE(data=consumption_fixture.quarry_PE_32, max_input_size=16)
    except consumption_bounds.quarry_LimitError:
        consumption_cases.append('installed input byte bound')
    else:
        raise AssertionError('input bound was not enforced')
    consumption_spec = consumption_util.spec_from_file_location('directory_fixtures', consumption_root/'checks/directory_fixtures.py')
    consumption_directories = consumption_util.module_from_spec(consumption_spec)
    consumption_spec.loader.exec_module(consumption_directories)
    consumption_payload = consumption_directories.dynamic_payload(symbol=7, payload=consumption_directories.override_payload())
    consumption_image, consumption_rva, consumption_raw = consumption_directories.image(consumption_reader, consumption_payload)
    consumption_results = consumption_image.parse_dynamic_relocations(consumption_rva-consumption_image.sections[0].VirtualAddress, 1)
    assert consumption_results[0].func_relocs[0].override_rvas == [0x210, 0x220]
    assert consumption_results[0].bdd_relocs[0].struct.Value == 0x230
    assert bytes(consumption_image.__data__) == consumption_raw
    consumption_cases.append('installed bounded dynamic function/BDD directory parsing')
    consumption_image, consumption_rva, _ = consumption_directories.image(consumption_reader, consumption_directories.relocation_payload(), max_directory_records=1)
    try:
        consumption_image.parse_image_base_relocation_list(consumption_rva, 12)
    except consumption_bounds.quarry_LimitError:
        consumption_cases.append('installed cumulative directory record bound')
    else:
        raise AssertionError('directory bound was not enforced')
    consumption_image, consumption_rva, _ = consumption_directories.image(consumption_reader, consumption_directories.exception_payload(), True)
    assert len(consumption_image.parse_exceptions_directory(consumption_rva, 12)) == 1
    consumption_cases.append('installed static runtime-function and unwind parsing')
    consumption_metadata = consumption_importlib.import_module('importlib.metadata')
    assert consumption_metadata.version('PEQuarry') == '1.0.2'
else:
    consumption_views = consumption_importlib.import_module('idbmeadow.semantic_views')
    consumption_examples = [('empty/empty.idb','d41d8cd98f00b204e9800998ecf8427e',(0,1)),('v6.95/x32/kernel32.idb','00bf1bf1b779ce1af41371426821e0c2',(1754271744,1755177520))]
    for consumption_relative, consumption_md5, consumption_bounds in consumption_examples:
        with consumption_module.meadow_from_file(path=str(consumption_root/'checks/data'/consumption_relative)) as consumption_database:
            consumption_metadata = consumption_views.meadow_Root(consumption_database)
            assert consumption_database.wordsize == 4
            assert consumption_metadata.version == 695
            assert consumption_metadata.md5 == consumption_md5
            consumption_api = consumption_module.meadow_IDAPython(consumption_database)
            assert (consumption_api.idc.MinEA(),consumption_api.idc.MaxEA()) == consumption_bounds
            consumption_cases.append('installed database metadata and emulated address bounds: '+consumption_relative)
print(consumption_json.dumps({'project':consumption_name,'status':'PASS','installed_source_files_identical':consumption_file_count,'consumer_checks_passed':len(consumption_cases),'checks':consumption_cases}))
