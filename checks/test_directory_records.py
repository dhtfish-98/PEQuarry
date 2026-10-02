"""Independent directory containment/progress cases; all sample bytes are static."""
import struct
import pytest
from pequarry import image_reader as reader
from pequarry import api_contract
from pequarry.bounded_io import quarry_LimitError
from checks.directory_fixtures import image, relocation_payload, override_payload, dynamic_payload, exception_payload


def warnings(pe):
    return '\n'.join(pe.get_warnings())


@pytest.mark.parametrize('is64', [False, True])
def test_normal_relocations_and_input_unchanged(is64):
    payload = relocation_payload() + bytes(8)
    pe, rva, raw = image(reader, payload, is64)
    blocks = pe.parse_relocations_directory(rva=rva, size=len(payload))
    assert len(blocks) == 2 and blocks[-1].struct.SizeOfBlock == 0
    assert [(entry.type, entry.rva) for entry in blocks[0].entries] == [(3, 0x210), (0, 0x212)]
    assert [entry.struct.get_file_offset() for entry in blocks[0].entries] == [rva + 8, rva + 10]
    assert bytes(pe.__data__) == raw and pe.write() == raw


@pytest.mark.parametrize('size', [1, 2, 7, 11, 13, 0xffffffff])
def test_block_cannot_leave_declared_directory(size):
    payload = struct.pack('<IIHH', 0x200, size, 0x3010, 0x3012)
    pe, rva, _ = image(reader, payload)
    assert pe.parse_image_base_relocation_list(rva, 12) == []
    assert 'relocation' in warnings(pe)
    assert pe._quarry_directory_count == 1


@pytest.mark.parametrize('size', range(1, 8))
def test_partial_declared_block_header_never_reads_outside(size):
    pe, rva, _ = image(reader, relocation_payload())
    calls = []
    original = pe.get_data
    pe.get_data = lambda *args: (calls.append(args), original(*args))[1]
    assert pe.parse_image_base_relocation_list(rva, size) == []
    assert not calls


def test_truncated_file_retains_complete_entries_with_warning():
    pe, rva, _ = image(reader, struct.pack('<HH', 0x3010, 0x3012), available=3)
    entries = pe.parse_relocations(rva, 0x200, 4)
    assert [(item.type, item.rva) for item in entries] == [(3, 0x210)]
    assert 'Incomplete relocation entry' in warnings(pe) and 'Truncated relocation data' in warnings(pe)


@pytest.mark.parametrize('bitfields', [False, True])
def test_duplicate_relocations_stop_and_preserve_prior_entries(bitfields):
    pe, rva, _ = image(reader, struct.pack('<HHH', 0x3010, 0x3010, 0x3012))
    if bitfields:
        entries = pe.parse_relocations_with_format(rva, 0x200, 6, pe.dynamic_relocation_format_by_symbol[5])
    else:
        entries = pe.parse_relocations(rva, 0x200, 6)
    assert len(entries) == 1 and 'Overlapping offsets' in warnings(pe)


@pytest.mark.parametrize('rva,size', [(-1, 0), (0, -1), (True, 0), (0, True), (1.5, 0), (0x100000000, 0)])
def test_invalid_public_directory_arguments(rva, size):
    pe, _, _ = image(reader)
    with pytest.raises(reader.PEFormatError): pe.parse_image_base_relocation_list(rva, size)
    with pytest.raises(reader.PEFormatError): pe.parse_relocations(rva, 0x200, size)


@pytest.mark.parametrize('value', [0, -1, True, 1.5])
def test_directory_limit_configuration(value):
    with pytest.raises(ValueError): image(reader, max_directory_records=value)


@pytest.mark.parametrize('kind', ['blocks', 'entries', 'override-rvas', 'exceptions'])
def test_cumulative_budget_covers_each_record_kind(kind):
    if kind == 'blocks':
        pe, rva, _ = image(reader, struct.pack('<II', 0x200, 8) * 3, max_directory_records=2)
        action = lambda: pe.parse_image_base_relocation_list(rva, 24)
    elif kind == 'entries':
        pe, rva, _ = image(reader, struct.pack('<HHH', 0x3010, 0x3012, 0x3014), max_directory_records=2)
        action = lambda: pe.parse_relocations(rva, 0x200, 6)
    elif kind == 'override-rvas':
        pe, rva, _ = image(reader, override_payload(), max_directory_records=3)
        action = lambda: pe.parse_function_override_data(rva)
    else:
        pe, rva, _ = image(reader, exception_payload(count=3), True, max_directory_records=2)
        action = lambda: pe.parse_exceptions_directory(rva, 36)
    with pytest.raises(quarry_LimitError, match='directory record'): action()
    assert pe._quarry_directory_count == pe._quarry_directory_limit + 1


def test_budget_is_not_reset_by_a_second_api_call():
    pe, rva, _ = image(reader, struct.pack('<H', 0x3010), max_directory_records=1)
    assert len(pe.parse_relocations(rva, 0x200, 2)) == 1
    with pytest.raises(quarry_LimitError): pe.parse_relocations(rva, 0x200, 2)


@pytest.mark.parametrize('is64', [False, True])
@pytest.mark.parametrize('symbol', [0, 3, 4, 5, 6, 7])
def test_normal_dynamic_records(is64, symbol):
    inner = override_payload() if symbol == 7 else relocation_payload(entries=(0x3010, 0x3012))
    if symbol == 3:
        inner = struct.pack('<IIII', 0x200, 16, 0x12345010, 0x12345012)
    payload = dynamic_payload(is64, symbol, inner)
    pe, rva, raw = image(reader, payload, is64)
    results = pe.parse_dynamic_relocations(rva - pe.sections[0].VirtualAddress, 1)
    assert len(results) == (0 if symbol == 0 else 1)
    if symbol == 7:
        assert results[0].func_relocs[0].override_rvas == [0x210, 0x220]
        assert results[0].bdd_relocs[0].struct.Value == 0x230
    elif symbol >= 3:
        assert len(results[0].relocations[0].entries) == 2
    assert bytes(pe.__data__) == raw


@pytest.mark.parametrize('is64', [False, True])
def test_dynamic_payload_cannot_escape_table(is64):
    payload = dynamic_payload(is64)
    # Leave the payload in the file, but exclude it from the declared table.
    raw = struct.pack('<II', 1, 12 if is64 else 8) + payload[8:]
    pe, rva, _ = image(reader, raw, is64)
    assert pe.parse_dynamic_relocations(rva - pe.sections[0].VirtualAddress, 1) == []
    assert 'dynamic payload exceeds table' in warnings(pe)


@pytest.mark.parametrize('available', range(8))
def test_truncated_dynamic_header_returns_none(available):
    pe, rva, _ = image(reader, dynamic_payload(), available=available)
    assert pe.parse_dynamic_relocations(rva - pe.sections[0].VirtualAddress, 1) is None
    assert 'IMAGE_DYNAMIC_RELOCATION_TABLE' in warnings(pe)


@pytest.mark.parametrize('offset,section', [(-1, 1), (True, 1), (0x100000000, 1), (1, -1), (1, True), (1, 1.5)])
def test_dynamic_arguments_reject_invalid_values(offset, section):
    pe, _, _ = image(reader)
    with pytest.raises(reader.PEFormatError): pe.parse_dynamic_relocations(offset, section)


@pytest.mark.parametrize('change', ['function-size', 'rva-size', 'reloc-size', 'bdd-size'])
def test_override_boundaries_are_enforced(change):
    raw = bytearray(override_payload())
    if change == 'function-size': struct.pack_into('<I', raw, 0, 1)
    elif change == 'rva-size': struct.pack_into('<I', raw, 12, 5)
    elif change == 'reloc-size': struct.pack_into('<I', raw, 16, 0xffffffff)
    else: struct.pack_into('<I', raw, 44, 9)
    pe, rva, _ = image(reader, raw)
    functions, bdd = pe.parse_function_override_data(rva)
    assert not bdd and ('Invalid function override' in warnings(pe))
    assert len(functions) == (1 if change == 'bdd-size' else 0)


def test_dynamic_function_override_obeys_outer_payload():
    inner = override_payload()
    payload = dynamic_payload(symbol=7, payload=inner)
    # Outer extent ends before the BDD header although bytes remain available.
    struct.pack_into('<I', raw := bytearray(payload), 12, len(inner) - 16)
    pe, rva, _ = image(reader, raw)
    results = pe.parse_dynamic_relocations(rva - pe.sections[0].VirtualAddress, 1)
    assert len(results) == 1 and len(results[0].func_relocs) == 1 and results[0].bdd_relocs == []
    assert 'record exceeds its declared container' in warnings(pe)


@pytest.mark.parametrize('count', [1, 2, 5])
def test_exception_records_share_complete_unwind_object(count):
    pe, rva, raw = image(reader, exception_payload(count=count), True)
    functions = pe.parse_exceptions_directory(rva, 12 * count)
    assert len(functions) == count
    assert all(item.unwindinfo is functions[0].unwindinfo for item in functions)
    assert sum(isinstance(item, reader.quarry_UnwindInfo) for item in pe.__structures__) == 1
    assert bytes(pe.__data__) == raw and pe.write() == raw


@pytest.mark.parametrize('available', [128, 129, 130, 131])
def test_truncated_unwind_is_warning_not_raw_exception(available):
    pe, rva, _ = image(reader, exception_payload(), True, available=available)
    assert pe.parse_exceptions_directory(rva, 12) == []
    assert 'Invalid exception information' in warnings(pe)


def test_partial_exception_directory_tail_is_reported():
    pe, rva, _ = image(reader, exception_payload(), True)
    assert len(pe.parse_exceptions_directory(rva, 13)) == 1
    assert 'Incomplete runtime function' in warnings(pe)


def test_exception_opcode_truncation_does_not_publish_incomplete_unwind():
    # UWOP_ALLOC_LARGE opinfo 1 requires three slots, CountOfCodes declares one.
    pe, rva, _ = image(reader, exception_payload(b'\x01\0\x01\0\x01\x11\0\0'), True)
    assert pe.parse_exceptions_directory(rva, 12) == []
    assert 'Invalid exception information' in warnings(pe)
    assert not any(isinstance(item, reader.quarry_UnwindInfo) for item in pe.__structures__)


def test_public_unwind_staged_size_contract():
    info = reader.quarry_UnwindInfo(file_offset=0x380)
    assert info.unpack_in_stages(b'\x01\0\x03\0') is None
    assert info.sizeof() == 12 and not info._finished_unpacking
    assert info.unpack_in_stages(b'\x01\0\x03\0\x01\x11') is None
    assert not info._finished_unpacking
    complete = b'\x01\0\x03\0\x01\x11' + struct.pack('<I', 0x1800) + bytes(2)
    assert info.unpack_in_stages(complete) is None
    assert info._finished_unpacking and len(info.UnwindCodes) == 1
    assert bytes(info.__pack__()) == complete


@pytest.mark.parametrize('flags', [0, 1, 2, 4])
def test_unwind_operands_cannot_consume_padding_or_optional_fields(flags):
    data = bytes([1 | (flags << 3), 0, 1, 0, 1, 0x11, 0, 0])
    if flags: data += struct.pack('<I', 0x210)
    info = reader.quarry_UnwindInfo(file_offset=0x380)
    message = info.unpack_in_stages(data)
    assert 'exceeds declared code slots' in message
    assert not info._finished_unpacking and info.UnwindCodes == []
    pe, rva, _ = image(reader, exception_payload(data), True)
    assert pe.parse_exceptions_directory(rva, 12) == []
    assert 'exceeds declared code slots' in warnings(pe)


def test_unwind_slot_budget_fails_before_operand_decode():
    data = b'\x01\0\x03\0\x01\x11' + struct.pack('<I', 0x1800) + bytes(2)
    pe, rva, _ = image(reader, exception_payload(data), True, max_directory_records=3)
    with pytest.raises(quarry_LimitError): pe.parse_exceptions_directory(rva, 12)
    assert not any(isinstance(item, reader.quarry_UnwindInfo) for item in pe.__structures__)


def test_finished_unwind_retains_staged_noop_contract():
    info = reader.quarry_UnwindInfo(file_offset=0x380)
    assert info.unpack_in_stages(b'\x01\0\0\0') is None
    assert info._finished_unpacking
    assert info.unpack_in_stages(b'') is None
    assert bytes(info.__pack__()) == b'\x01\0\0\0'


def test_dynamic_table_stays_inside_selected_raw_section():
    pe, rva, _ = image(reader, dynamic_payload())
    pe.sections[0].SizeOfRawData = rva + 8 - pe.sections[0].VirtualAddress
    assert pe.parse_dynamic_relocations(rva - pe.sections[0].VirtualAddress, 1) == []
    assert 'dynamic table exceeds selected section' in warnings(pe)


def test_dynamic_header_cannot_start_outside_selected_raw_section():
    pe, rva, _ = image(reader, dynamic_payload())
    pe.sections[0].SizeOfRawData = rva - pe.sections[0].VirtualAddress
    assert pe.parse_dynamic_relocations(rva - pe.sections[0].VirtualAddress, 1) is None
    assert 'record exceeds its declared container' in warnings(pe)
