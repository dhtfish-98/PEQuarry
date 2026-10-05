"""Focused regressions using a complete, never-executed PE32 test image."""

import struct

from checks.directory_fixtures import embedded_bytes
from pequarry.image_reader import PE, Structure


def debug_image(payload):
    raw = bytearray(embedded_bytes())
    header = PE(data=raw, fast_load=True)
    debug_directory = header.OPTIONAL_HEADER.DATA_DIRECTORY[6]
    struct.pack_into('<II', raw, debug_directory.get_file_offset(), 0x400, 28)
    struct.pack_into('<IIHHIIII', raw, 0x400, 0, 0, 0, 0, 20, len(payload), 0x430, 0x430)
    raw[0x430:0x430 + len(payload)] = payload
    return bytes(raw)


def delay_import_image():
    raw = bytearray(embedded_bytes())
    header = PE(data=raw, fast_load=True)
    raw.extend(bytes(0x6d0 - len(raw)))
    optional = header.OPTIONAL_HEADER
    section = header.sections[0]
    struct.pack_into('<I', raw, optional.get_field_absolute_offset('ImageBase'), 0x400000)
    struct.pack_into('<I', raw, optional.get_field_absolute_offset('SizeOfImage'), 0x2000)
    struct.pack_into('<I', raw, section.get_field_absolute_offset('Misc_VirtualSize'), 0x500)
    struct.pack_into('<I', raw, section.get_field_absolute_offset('SizeOfRawData'), 0x500)
    directory = optional.DATA_DIRECTORY[13]
    struct.pack_into('<II', raw, directory.get_file_offset(), 0x460, 64)
    struct.pack_into('<IIIIIIII', raw, 0x460,
                     0, 0x4004f0, 0x4004d0, 0x4004c0,
                     0x4004b0, 0, 0x4004e0, 0)
    struct.pack_into('<I', raw, 0x4b0, 0x400500)
    struct.pack_into('<I', raw, 0x4c0, 0x400500)
    raw[0x4f0:0x4f8] = b'OWN.dll\0'
    raw[0x500:0x50c] = b'\0\0OwnedFunc\0'
    return bytes(raw)


def guard_rf_relocation_image(failure_pointer, verify_pointer):
    raw = bytearray(embedded_bytes(True))
    header = PE(data=raw, fast_load=True)
    raw.extend(bytes(0xa00 - len(raw)))
    optional = header.OPTIONAL_HEADER
    section = header.sections[0]
    old_base = 0x180000000
    for structure, field, value, code in (
        (optional, 'ImageBase', old_base, '<Q'),
        (optional, 'SizeOfImage', 0x2000, '<I'),
        (section, 'Misc_VirtualSize', 0x820, '<I'),
        (section, 'SizeOfRawData', 0x820, '<I'),
    ):
        struct.pack_into(code, raw, structure.get_field_absolute_offset(field), value)
    for index, rva, size in ((5, 0x780, 12), (10, 0x600, 240)):
        struct.pack_into('<II', raw, optional.DATA_DIRECTORY[index].get_file_offset(), rva, size)
    load = Structure(header.__IMAGE_LOAD_CONFIG_DIRECTORY64_format__)
    struct.pack_into('<I', raw, 0x600, 240)
    for field, value in (
        ('GuardRFFailureRoutineFunctionPointer', failure_pointer),
        ('GuardRFVerifyStackPointerFunctionPointer', verify_pointer),
    ):
        struct.pack_into('<Q', raw, 0x600 + load.get_field_relative_offset(field), value)
    struct.pack_into('<Q', raw, 0x720, old_base + 0x500)
    struct.pack_into('<IIHH', raw, 0x780, 0x700, 12, 0xa020, 0)
    return bytes(raw)


def test_short_type20_debug_record_does_not_abort_complete_pe_parse(tmp_path):
    malformed = debug_image(b'')
    path = tmp_path / 'short-debug.dll'
    path.write_bytes(malformed)
    for supplied in (malformed, path):
        image = PE(data=supplied) if isinstance(supplied, bytes) else PE(supplied)
        assert len(image.DIRECTORY_ENTRY_DEBUG) == 1
        assert image.DIRECTORY_ENTRY_DEBUG[0].struct.Type == 20
        assert image.DIRECTORY_ENTRY_DEBUG[0].entry is None


def test_complete_type20_debug_record_still_decodes_flags():
    image = PE(data=debug_image(struct.pack('<I', 1)))
    entry = image.DIRECTORY_ENTRY_DEBUG[0].entry
    assert entry.ExDllCharacteristics == 1


def test_delay_import_phmod_normalizes_its_own_field_from_full_image(tmp_path):
    raw = delay_import_image()
    path = tmp_path / 'delay-import.dll'
    path.write_bytes(raw)
    for supplied in (raw, path):
        image = PE(data=supplied) if isinstance(supplied, bytes) else PE(supplied)
        assert len(image.DIRECTORY_ENTRY_DELAY_IMPORT) == 1
        descriptor = image.DIRECTORY_ENTRY_DELAY_IMPORT[0]
        assert descriptor.struct.grAttrs == 0
        assert descriptor.struct.phmod == 0x4d0
        assert descriptor.struct.pUnloadIAT == 0x4e0
        assert descriptor.dll == b'OWN.dll'
        assert [symbol.name for symbol in descriptor.imports] == [b'OwnedFunc']


def test_guard_rf_pointers_relocate_once_from_complete_pe32_plus_image(tmp_path):
    old_base = 0x180000000
    for failure, verify in ((old_base + 0x100, old_base + 0x200),
                            (old_base + 0x100, 0)):
        raw = guard_rf_relocation_image(failure, verify)
        path = tmp_path / 'guard-rf.dll'
        path.write_bytes(raw)
        image = PE(path)
        assert image.OPTIONAL_HEADER.ImageBase == old_base
        assert len(image.DIRECTORY_ENTRY_BASERELOC) == 1
        load = image.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        assert load.GuardRFFailureRoutineFunctionPointer == failure
        assert load.GuardRFVerifyStackPointerFunctionPointer == verify
        image.relocate_image(old_base + 0x1000)
        assert image.OPTIONAL_HEADER.ImageBase == old_base + 0x1000
        assert image.get_qword_at_rva(0x720) == old_base + 0x1500
        assert load.GuardRFFailureRoutineFunctionPointer == failure + 0x1000
        assert load.GuardRFVerifyStackPointerFunctionPointer == (
            verify + 0x1000 if verify else 0)
