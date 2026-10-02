"""Owned synthetic directory bytes based on attributed embedded PE headers.

No fixture is loaded as an executable; only byte layout is inspected.
"""
import ast
from pathlib import Path
import struct


def embedded_bytes(is64=False):
    name = 'quarry_PE_64' if is64 else 'quarry_PE_32'
    tree = ast.parse(Path(__file__).with_name('test_quarry_export_test.py').read_text())
    node = next(node for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets))
    return bytes.fromhex(ast.literal_eval(node.value.args[0].args[0]).decode())


def image(module, payload=b'', is64=False, position=0x300, available=None, **options):
    raw = bytearray(embedded_bytes(is64))
    assert position >= 0x300 and position + len(payload) <= len(raw)
    raw[position:position + len(payload)] = payload
    if available is not None:
        raw = raw[:position + available]
    pe = module.PE(data=bytes(raw), fast_load=True, **options)
    return pe, position, bytes(raw)


def relocation_payload(entries=(0x3010, 0x0012), base=0x200):
    body = struct.pack('<' + 'H' * len(entries), *entries)
    return struct.pack('<II', base, 8 + len(body)) + body


def override_payload():
    block = relocation_payload()
    record = struct.pack('<IIII', 0x200, 0, 8, len(block)) + struct.pack('<II', 0x210, 0x220) + block
    return struct.pack('<I', len(record)) + record + struct.pack('<IIHHI', 1, 8, 0, 1, 0x230)


def dynamic_payload(is64=False, symbol=6, payload=None):
    payload = relocation_payload() if payload is None else payload
    record = struct.pack('<QI' if is64 else '<II', symbol, len(payload)) + payload
    return struct.pack('<II', 1, len(record)) + record


def exception_payload(unwind=b'\x01\0\0\0', count=1):
    entries = b''.join(struct.pack('<III', 0x200 + 16*i, 0x210 + 16*i, 0x380) for i in range(count))
    assert len(entries) <= 0x80
    return entries + bytes(0x80 - len(entries)) + unwind


def normalize_blocks(blocks):
    return [{'header': block.struct.__pack__().hex(), 'offset': block.struct.get_file_offset(), 'entries': [{'fields': entry.struct.__pack__().hex(), 'offset': entry.struct.get_file_offset(), 'rva': entry.rva, 'type': getattr(entry, 'type', None)} for entry in block.entries]} for block in blocks]
