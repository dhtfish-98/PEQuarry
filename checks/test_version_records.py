"""Independent fields/lengths/progress/edit assertions for owned version bytes."""
from types import SimpleNamespace
import struct
import pytest
from pequarry import image_reader as reader
from pequarry.bounded_io import quarry_LimitError
from checks.test_resource_records import fixture
from checks.resource_fixtures import BASE, block, string_entry, version_payload








def parse(payload, resource_size=None, **options):
    pe, raw = fixture(payload, **options)
    pe.parse_version_information(SimpleNamespace(OffsetToData=BASE, Size=len(payload) if resource_size is None else resource_size))
    return pe, raw


@pytest.mark.parametrize('text', ['owned', '', 'é', '中文', '😀'])
def test_independent_version_fields_and_unicode(text):
    pe, raw = parse(version_payload(entries=(('CompanyName', text),)))
    assert pe.VS_VERSIONINFO[0].Key == b'VS_VERSION_INFO' and pe.VS_VERSIONINFO[0].metadata_complete
    fixed = pe.VS_FIXEDFILEINFO[0]
    assert fixed.Signature == 0xfeef04bd and fixed.FileVersionMS == 0x10002
    strings, variables = pe.FileInfo[0]
    assert strings.StringTable[0].entries == {b'CompanyName': text.encode()}
    assert variables.Var[0].entry == {b'Translation': '0x0409 0x04b0'}
    assert variables.Var[0].translations == [(0x409, 1200)]
    assert bytes(pe.__data__) == raw and pe.write() == raw


@pytest.mark.parametrize('strings,var,fixed', [(False, False, True), (False, False, False), (True, False, False), (False, True, False)])
def test_optional_version_children_and_value(strings, var, fixed):
    pe, _ = parse(version_payload(include_strings=strings, include_var=var, fixed=fixed))
    assert pe.VS_VERSIONINFO[0].metadata_complete
    assert bool(getattr(pe, 'VS_FIXEDFILEINFO', [])) == fixed
    assert len(pe.FileInfo) == int(strings or var)
    assert not any('StringFileInfo/VarFileInfo' in message for message in pe.get_warnings())


def test_multiple_string_tables_are_each_parsed():
    pe, _ = parse(version_payload(languages=('040904b0', '080404b0'), include_var=False))
    tables = pe.FileInfo[0][0].StringTable
    assert [table.LangID for table in tables] == [b'040904b0', b'080404b0']
    assert all(table.entries == {b'CompanyName': b'owned'} for table in tables)


def test_multiple_var_records_and_translation_pairs_are_retained():
    values = [block('Translation', struct.pack('<4H', 0x409, 1200, 0x804, 936), kind=0), block('Other', struct.pack('<2H', 0x411, 932), kind=0)]
    pe, _ = parse(block('VS_VERSION_INFO', children=[block('VarFileInfo', children=values)], kind=0))
    variables = pe.FileInfo[0][0].Var
    assert len(variables) == 2
    assert variables[0].translations == [(0x409, 1200), (0x804, 936)]
    assert variables[0].entry == {b'Translation': '0x0804 0x03a8'}
    assert variables[1].entry == {b'Other': '0x0411 0x03a4'}


@pytest.mark.parametrize('length', [0, 1, 5, 0xffff])
def test_root_length_must_fit_resource_and_advance(length):
    payload = bytearray(version_payload())
    struct.pack_into('<H', payload, 0, length)
    pe, _ = parse(payload)
    assert not getattr(pe, 'VS_VERSIONINFO', [])
    assert any('version block extent' in message for message in pe.get_warnings())


@pytest.mark.parametrize('size', [0, 1, 5, 38, 90])
def test_declared_version_resource_bounds_are_enforced(size):
    pe, _ = parse(version_payload(), size)
    assert not getattr(pe, 'VS_VERSIONINFO', []) or not pe.VS_VERSIONINFO[0].metadata_complete
    assert any('version' in message.lower() for message in pe.get_warnings())


@pytest.mark.parametrize('target', ['StringFileInfo', '040904b0', 'CompanyName'])
@pytest.mark.parametrize('length', [0, 1, 5, 0xffff])
def test_child_lengths_cannot_repeat_or_escape_parent(target, length):
    payload = bytearray(version_payload())
    offset = payload.index((target + '\0').encode('utf-16le')) - 6
    struct.pack_into('<H', payload, offset, length)
    pe, _ = parse(payload)
    assert not pe.VS_VERSIONINFO[0].metadata_complete
    assert any('version block extent' in message for message in pe.get_warnings())


def test_version_key_cannot_search_beyond_child_block():
    payload = bytearray(version_payload())
    offset = payload.index('CompanyName\0'.encode('utf-16le')) - 6
    # The child contains a six-byte header and one nonzero UTF-16 unit only.
    struct.pack_into('<H', payload, offset, 8)
    pe, _ = parse(payload)
    assert not pe.VS_VERSIONINFO[0].metadata_complete
    assert any('unterminated version key' in message for message in pe.get_warnings())


def test_string_value_length_uses_utf16_units_and_parent_bytes():
    payload = bytearray(version_payload())
    offset = payload.index('CompanyName\0'.encode('utf-16le')) - 6
    struct.pack_into('<H', payload, offset + 2, 0xffff)
    pe, _ = parse(payload)
    assert not pe.VS_VERSIONINFO[0].metadata_complete
    assert any('String.ValueLength' in message for message in pe.get_warnings())


@pytest.mark.parametrize('length', [1, 3, 0xffff])
def test_var_translation_alignment_and_extent(length):
    payload = bytearray(version_payload())
    offset = payload.index('Translation\0'.encode('utf-16le')) - 6
    struct.pack_into('<H', payload, offset + 2, length)
    pe, _ = parse(payload)
    assert not pe.VS_VERSIONINFO[0].metadata_complete
    assert any('translation extent/alignment' in message for message in pe.get_warnings())


@pytest.mark.parametrize('limit', [1, 3, 8, 16, 32])
def test_version_records_and_utf16_units_share_budget(limit):
    pe, _ = fixture(version_payload(), max_directory_records=limit)
    with pytest.raises(quarry_LimitError): pe.parse_version_information(SimpleNamespace(OffsetToData=BASE, Size=len(version_payload())))


def test_unicode_edit_cannot_touch_adjacent_version_record():
    pe, raw = parse(version_payload(entries=(('A', '中文'), ('B', 'sentinel')), include_var=False))
    table = pe.FileInfo[0][0].StringTable[0]
    assert table.entries_lengths[b'A'][1] == 6  # historical UTF-8-byte field
    assert table._quarry_value_capacities[b'A'] == 2  # actual UTF-16 cells
    first_value = table.entries_offsets[b'A'][1]
    table.entries[b'A'] = b'ABCDEFGH'
    output = pe.write()
    assert output[first_value:first_value + 4] == 'AB'.encode('utf-16le')
    assert output[first_value + 4:] == raw[first_value + 4:]
    assert len(output) == len(raw)
