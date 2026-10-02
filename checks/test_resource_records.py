"""Independent static resource boundaries and explicit incomplete-tree cases."""
from types import SimpleNamespace
import struct
import pytest
from pequarry import image_reader as reader
from pequarry import api_contract
from pequarry import resource_records
from pequarry.bounded_io import quarry_LimitError
from checks.resource_fixtures import BASE, header, tree_payload, make_image

def fixture(payload, available=None, **options):
    return make_image(reader, payload, available, **options)








def leaves(root):
    return root.entries[0].directory.entries[0].directory.entries


@pytest.mark.parametrize('size', [0, 88, 101])
def test_normal_metadata_preserves_fields_and_bytes(size):
    payload = tree_payload()
    pe, raw = fixture(payload)
    root = pe.parse_resources_directory(BASE, size)
    assert root.metadata_complete and leaves(root)[0].data.lang == 9
    assert leaves(root)[0].data.sublang == 1
    assert leaves(root)[0].data.struct.CodePage == 1200
    assert leaves(root)[0].data.struct.OffsetToData == BASE + 96
    assert bytes(pe.__data__) == raw and pe.write() == raw


@pytest.mark.parametrize('size', [1, 15, 16, 23, 24, 39, 40, 47, 48, 63, 64, 71, 72, 87])
def test_declared_metadata_extent_blocks_later_file_bytes(size):
    pe, _ = fixture(tree_payload())
    calls = []
    original = pe.get_data
    pe.get_data = lambda rva, length=None: (calls.append((rva, length)), original(rva, length))[1]
    root = pe.parse_resources_directory(BASE, size)
    assert root is None or not root.metadata_complete
    assert all(rva + length <= BASE + size for rva, length in calls)
    assert pe.get_warnings()


@pytest.mark.parametrize('available', [0, 1, 6, 15, 16, 20, 24, 40, 48, 64, 72, 80, 87])
def test_short_physical_metadata_retains_only_verified_records(available):
    pe, _ = fixture(tree_payload(), available=available)
    root = pe.parse_resources_directory(BASE)
    assert root is None or not root.metadata_complete
    assert pe.get_warnings()


def test_cycle_stops_with_explicit_incomplete_tree():
    pe, _ = fixture(header() + struct.pack('<II', 10, 0x80000000))
    root = pe.parse_resources_directory(BASE)
    assert root.entries == [] and not root.metadata_complete
    assert pe._quarry_directory_count == 2


def test_iterative_depth_does_not_depend_on_python_recursion(monkeypatch):
    count = 1100
    payload = b''.join(header() + struct.pack('<II', 10, 0x80000000 | ((index+1)*24)) for index in range(count)) + header(ids=0)
    pe, _ = fixture(payload)
    monkeypatch.setattr(reader, 'MAX_RESOURCE_DEPTH', count + 1)
    root = pe.parse_resources_directory(BASE, len(payload))
    for _ in range(count):
        assert root.metadata_complete
        root = root.entries[0].directory
    assert root.entries == []


def test_depth_limit_propagates_incompleteness():
    pe, _ = fixture(header() + struct.pack('<II', 10, 0x80000018) + header(ids=0))
    root = pe.parse_resources_directory(BASE, level=reader.MAX_RESOURCE_DEPTH)
    assert not root.metadata_complete and root.entries == []
    assert any('Excessively nested' in message for message in pe.get_warnings())


@pytest.mark.parametrize('count', [4097, 65535])
def test_entry_counts_rejected_before_traversal(count):
    pe, _ = fixture(header(ids=count))
    assert pe.parse_resources_directory(BASE) is None
    assert pe._quarry_directory_count == 1


def test_resource_global_entry_count_budget_remains_enforced():
    pe, _ = fixture(tree_payload())
    api_contract.attributes(pe)['__total_resource_entries_count'] = reader.MAX_RESOURCE_ENTRIES
    assert pe.parse_resources_directory(BASE) is None
    assert 'file contains at least' in '\n'.join(pe.get_warnings())


@pytest.mark.parametrize('limit', [1, 2, 4, 6])
def test_directory_budget_covers_resource_headers_and_entries(limit):
    pe, _ = fixture(tree_payload(), max_directory_records=limit)
    with pytest.raises(quarry_LimitError): pe.parse_resources_directory(BASE)


@pytest.mark.parametrize('name', ['owned', '中文', '😀'])
def test_named_resource_wrapper_is_owned_and_bounded(name):
    # UTF-16 code-unit count differs from Python character count for astral text.
    payload = bytearray(tree_payload(name=name))
    offset = struct.unpack_from('<I', payload, 16)[0] & 0x7fffffff
    struct.pack_into('<H', payload, offset, len(name.encode('utf-16le')) // 2)
    pe, raw = fixture(payload)
    root = pe.parse_resources_directory(BASE, len(payload))
    assert root.metadata_complete and root.entries[0].id is None
    assert str(root.entries[0].name) == name
    assert root.entries[0].name.get_rva() == BASE + offset
    assert bytes(pe.__data__) == raw


def test_named_resource_cannot_read_beyond_declared_span():
    payload = tree_payload(name='owned')
    pe, _ = fixture(payload)
    root = pe.parse_resources_directory(BASE, len(payload) - 2)
    assert not root.metadata_complete and root.entries[0].name is None
    assert any('unicode string' in message for message in pe.get_warnings())


def test_name_unit_budget_is_charged_before_decode():
    pe, _ = fixture(tree_payload(name='long-name'), max_directory_records=5)
    with pytest.raises(quarry_LimitError): pe.parse_resources_directory(BASE)


@pytest.mark.parametrize('size,level', [(-1, 0), (True, 0), (1.5, 0), (0, -1), (0, True), (0, 1.5)])
def test_invalid_resource_public_arguments(size, level):
    pe, _ = fixture(header(ids=0))
    with pytest.raises(reader.PEFormatError): pe.parse_resources_directory(BASE, size=size, level=level)


def test_string_resource_values_and_decode_status():
    data = struct.pack('<H', 3) + 'ABC'.encode('utf-16le') + bytes(30)
    pe, _ = fixture(tree_payload(kind=6, strings=data))
    root = pe.parse_resources_directory(BASE)
    strings = root.entries[0].directory.entries[0].directory
    assert strings.strings == {0: 'ABC'} and strings.strings_complete


def test_short_string_value_is_retained_and_marked_incomplete():
    data = struct.pack('<H', 4) + 'ABC'.encode('utf-16le')
    pe, _ = fixture(tree_payload(kind=6, strings=data))
    root = pe.parse_resources_directory(BASE)
    strings = root.entries[0].directory.entries[0].directory
    assert strings.strings == {0: 'ABC'} and not strings.strings_complete


def test_unsigned_string_length_is_not_treated_as_negative():
    data = struct.pack('<H', 0x8000) + 'A'.encode('utf-16le') * 0x8000
    output = {}
    assert reader.parse_strings(data, 7, output) is None
    assert output == {7: 'A'*0x8000}


def test_standalone_string_parser_reports_odd_and_invalid_units():
    output = {}
    assert resource_records.parse_strings(b'\x01\0A', 0, output)
    assert output == {}
    assert resource_records.parse_strings(b'\x01\0\0\xd8', 0, output)
    assert output == {}


def test_string_resource_span_budget_precedes_large_read():
    payload = bytearray(tree_payload(kind=6, strings=b'A'))
    struct.pack_into('<I', payload, 76, 0xffffffff)
    pe, _ = fixture(payload)
    # Invalid 32-bit spans yield a resource error; no giant data request occurs.
    calls = []
    original = pe.get_data
    pe.get_data = lambda rva, length=None: (calls.append(length), original(rva, length))[1]
    root = pe.parse_resources_directory(BASE)
    assert not root.entries[0].directory.entries[0].directory.strings_complete
    assert max(calls) <= 16


def test_partly_overlapping_names_stop_with_metadata_status():
    payload = header(named=2, ids=0) + struct.pack('<IIII', 0x80000040, 32, 0x80000044, 48)
    payload += struct.pack('<IIII', 0, 0, 0, 0) * 2
    payload += struct.pack('<4H', 2, ord('A'), 1, ord('B'))
    pe, _ = fixture(payload)
    root = pe.parse_resources_directory(BASE, len(payload))
    assert len(root.entries) == 1 and not root.metadata_complete
    assert any('Entry names overlap' in message for message in pe.get_warnings())


def test_exact_shared_name_reference_is_allowed():
    payload = header(named=2, ids=0) + struct.pack('<IIII', 0x80000040, 32, 0x80000040, 48)
    payload += struct.pack('<IIII', 0, 0, 0, 0) * 2
    payload += struct.pack('<H', 2) + 'AB'.encode('utf-16le')
    pe, _ = fixture(payload)
    root = pe.parse_resources_directory(BASE, len(payload))
    assert root.metadata_complete and [str(entry.name) for entry in root.entries] == ['AB', 'AB']
