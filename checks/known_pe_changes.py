"""Two exact source corrections, independently decoded from frozen bytes."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys

if __package__:
    from .observation_json import typed
    from .version_byte_evidence import decode, expected_file_info
else:
    from observation_json import typed
    from version_byte_evidence import decode, expected_file_info

FILES = {
    'corkami/pocs/version_cust.exe': '60b50d9a03b2580a4ec8d7d3da230dc3f62ec5489ec81e15b690fb39a3c78a27',
    'corkami/pocs/version_std.exe': '927081b2c9548694c85e46aa2c6d965fc43ed5121aa4d47fbcda3d990996a592',
}
REMOVED = ['Corrupt header "StringFileInfo" at file offset 692. Exception: \'Data length less than expected header length.\'', 'Error parsing StringFileInfo/VarFileInfo struct']
EVIDENCE = Path(__file__).resolve().parents[1] / 'REVIEWED_VERSION_CHANGES.json'


def source_module(baseline):
    sys.path.insert(0, str(baseline))
    try:
        spec = importlib.util.spec_from_file_location('frozen_version_control', Path(baseline)/'pefile.py')
        source = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(source)
        return source
    finally:
        sys.path.pop(0)


def verify_changes(baseline, dataset):
    from pequarry import image_reader
    source = source_module(baseline)
    contracts = []
    for filename, sha256 in FILES.items():
        raw = (Path(dataset)/filename).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == sha256
        evidence = decode(raw)
        old, new = source.PE(data=raw), image_reader.PE(data=raw)
        assert new.VS_VERSIONINFO[0].metadata_complete
        assert old.VS_VERSIONINFO[0].get_file_offset() == new.VS_VERSIONINFO[0].get_file_offset() == 600
        assert new.write() == old.write() == raw
        before, after = old.dump_dict(), new.dump_dict()
        if filename.endswith('version_cust.exe'):
            assert evidence['root']['length'] == 92 and evidence['root']['end'] == 692
            assert evidence['groups'] == [] and old.FileInfo == new.FileInfo == []
            assert old.get_warnings()[-2:] == REMOVED
            assert new.get_warnings() == old.get_warnings()[:-2]
            expected_text = old.dump_info()
            for warning in REMOVED:
                assert expected_text.count(warning+'\n\n') == 1
                expected_text = expected_text.replace(warning+'\n\n', '')
            expected_dict = old.dump_dict()
            expected_dict['Parsing Warnings'] = old.get_warnings()[:-2]
            assert expected_dict == after and expected_text == new.dump_info()
            change = 'Only two spurious missing-optional-Children warnings removed; root ends exactly after its fixed value.'
        else:
            assert evidence['root']['length'] == 1060
            assert [(v['offset'], v['length'], v['key']) for v in evidence['groups']] == [(692,900,'StringFileInfo'), (1592,68,'VarFileInfo')]
            table = evidence['groups'][0]['children'][0]
            assert (table['offset'], table['length'], len(table['children'])) == (728,864,17)
            assert [entry['value'] for entry in table['children'] if entry['key']=='FileVersion'] == ['compulsory for version tab','duplicates are authorized']
            var = evidence['groups'][1]['children'][0]
            assert (var['offset'],var['length'],var['value_length'],var['translations']) == (1624,36,4,[(0,0)])
            expected = source.PE(data=raw)
            expected.FileInfo = expected_file_info(source, expected, evidence, raw)
            # The original formatter renders independently decoded structures.
            # This validates every corrected field and the entire text/dict dump.
            assert expected.dump_dict() == after and expected.dump_info() == new.dump_info()
            untouched_before = {key:value for key,value in before.items() if key != 'Version Information'}
            untouched_after = {key:value for key,value in after.items() if key != 'Version Information'}
            assert untouched_before == untouched_after and old.get_warnings() == new.get_warnings()
            table_new = new.FileInfo[0][0].StringTable[0]
            table_expected = expected.FileInfo[0][0].StringTable[0]
            assert table_new.entries == table_expected.entries
            assert table_new.entries_offsets == table_expected.entries_offsets
            assert table_new.entries_lengths == table_expected.entries_lengths
            assert new.FileInfo[0][1].Var[0].translations == [(0,0)]
            change = 'Follow all 17 contained String records (16 final keys, last duplicate wins) and the contained Var translation, using each declared byte/UTF-16 length.'
        contracts.append({'file':filename, 'input_sha256':sha256, 'change':change,
            'independent_byte_fields':evidence,
            'source_version_information':typed(before.get('Version Information')),
            'current_version_information':typed(after.get('Version Information')),
            'source_warnings':old.get_warnings(), 'current_warnings':new.get_warnings(),
            'source_actual_dump_info':old.dump_info(), 'current_actual_dump_info':new.dump_info(),
            'all_other_dump_fields_and_serialized_bytes_equal':True})
    return contracts


def compare(old, new, baseline, dataset):
    assert len(old) == len(new)
    changed = [(left,right) for left,right in zip(old,new) if left != right]
    assert len(changed) == len(FILES), 'Unexpected number of PE observation changes'
    assert {left['file'] for left,right in changed} == set(FILES)
    for left,right in changed:
        filename = left['file']
        assert right['file'] == filename
        assert left['input_sha256'] == right['input_sha256'] == FILES[filename]
        expected = {'dump_info_sha256','dump_dict_sha256'}
        if filename.endswith('version_cust.exe'):
            expected.add('warnings')
            assert left['warnings'][-2:] == REMOVED and right['warnings'] == left['warnings'][:-2]
        assert {key for key in left.keys()|right.keys() if left.get(key)!=right.get(key)} == expected
        assert 'error_type' not in left and 'error_type' not in right
    contracts = verify_changes(baseline,dataset)
    frozen = {'source_commit':'e521f469b41abb074bae1cc0820396d6f7663cd9',
        'test_commit':'7fb3461fda128b4f7864c0891e03babbe43f6d9b',
        'observer':'Lossless typed-key JSON; mixed byte/text keys no longer hide version_std fields behind TypeError.',
        'reviewed_changes':contracts,
        'source_observations':[left for left,right in changed], 'current_observations':[right for left,right in changed]}
    assert json.loads(EVIDENCE.read_text()) == json.loads(json.dumps(frozen)), 'Frozen version correction evidence differs'
    return {'compared':len(old), 'unchanged':len(old)-len(changed),
        'reviewed_changes':[{'file':contract['file'],'input_sha256':contract['input_sha256'],'change':contract['change'],'all_other_dump_fields_and_serialized_bytes_equal':True} for contract in contracts],
        'independent_byte_evidence':'REVIEWED_VERSION_CHANGES.json'}
