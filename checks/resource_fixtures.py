"""Owned static resource/version builders; no PE image is executed."""
import struct
try:
    from .directory_fixtures import embedded_bytes
except ImportError:
    from directory_fixtures import embedded_bytes

BASE = 0x300

def header(named=0, ids=1):
    return struct.pack('<IIHHHH', 0, 0, 0, 0, named, ids)

def tree_payload(kind=10, strings=None, name=None):
    payload = header() + struct.pack('<II', kind, 0x80000018)
    payload += header() + struct.pack('<II', 1, 0x80000030)
    payload += header() + struct.pack('<II', 0x409, 72)
    data = b'owned' if strings is None else strings
    payload += struct.pack('<IIII', BASE + 96, len(data), 1200, 0) + bytes(8) + data
    if name is not None:
        name_offset = len(payload)
        payload = bytearray(payload)
        struct.pack_into('<HH', payload, 12, 1, 0)
        struct.pack_into('<I', payload, 16, 0x80000000 | name_offset)
        payload += struct.pack('<H', len(name)) + name.encode('utf-16le')
    return bytes(payload)

def block(key, value=b'', children=(), value_length=None, kind=1):
    key_bytes = (key + '\0').encode('utf-16le')
    data = bytearray(struct.pack('<HHH', 0, 0, kind) + key_bytes)
    data += bytes((-len(data)) & 3)
    data += value
    for child in children:
        data += bytes((-len(data)) & 3)
        data += child
    units = len(value)//2 if kind == 1 else len(value)
    struct.pack_into('<HH', data, 0, len(data), units if value_length is None else value_length)
    return bytes(data)

def string_entry(key, text):
    return block(key, (text + '\0').encode('utf-16le'))

def version_payload(entries=(('CompanyName', 'owned'),), languages=('040904b0',), include_var=True, include_strings=True, fixed=True):
    fixed_bytes = struct.pack('<13I', 0xfeef04bd, 0x10000, 0x10002, 0x30004, 0x50006, 0x70008, 0x3f, 0, 0x40004, 1, 0, 0, 0) if fixed else b''
    children = []
    if include_strings:
        tables = [block(language, children=[string_entry(key, value) for key, value in entries]) for language in languages]
        children.append(block('StringFileInfo', children=tables))
    if include_var:
        translation = block('Translation', struct.pack('<HH', 0x409, 1200), kind=0)
        children.append(block('VarFileInfo', children=[translation]))
    return block('VS_VERSION_INFO', fixed_bytes, children, kind=0)

def make_image(module, payload, available=None, **options):
    raw = bytearray(embedded_bytes())
    raw.extend(bytes(max(0, BASE + len(payload) - len(raw))))
    raw[BASE:BASE + len(payload)] = payload
    if available is not None: raw = raw[:BASE + available]
    pe = module.PE(data=bytes(raw), fast_load=True, **options)
    if BASE + len(payload) > len(embedded_bytes()):
        pe.sections[0].SizeOfRawData = len(raw) - pe.sections[0].PointerToRawData
        pe.sections[0].Misc_VirtualSize = pe.sections[0].SizeOfRawData
    return pe, bytes(raw)
