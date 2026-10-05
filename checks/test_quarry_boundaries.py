"""Independent finite-input cases; no PE sample is executed."""
from pathlib import Path
from types import SimpleNamespace
import hashlib
import os
import random
import struct
import subprocess
import sys
import tracemalloc
import pytest
from pequarry import image_reader as reader
from pequarry import signature_tools as signatures
from pequarry.bounded_io import quarry_LimitError, quarry_read_regular
from checks.test_quarry_export_test import quarry_PE_32, quarry_PE_64


def image(raw=quarry_PE_32, **options):
    return reader.PE(data=raw, **options)


def test_scalar_rva_reads_do_not_copy_the_entire_section():
    original = image(fast_load=True)
    section_header_offset = original.sections[0].get_file_offset()
    section_size = 8 * 1024 * 1024
    raw = bytearray(quarry_PE_32) + bytearray(section_size)
    struct.pack_into('<I', raw, section_header_offset + 16, section_size)
    pe = image(raw, fast_load=True)
    section = pe.sections[0]
    for method, width in ((pe.get_word_at_rva, 2), (pe.get_qword_at_rva, 8)):
        tracemalloc.start()
        try:
            result = method(section.VirtualAddress)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        expected = int.from_bytes(raw[section.PointerToRawData:section.PointerToRawData + width], 'little')
        assert result == expected
        assert peak < 1024 * 1024


@pytest.mark.parametrize(('width', 'data_method', 'file_method'), (
    (2, 'get_word_from_data', 'get_word_from_offset'),
    (4, 'get_dword_from_data', 'get_dword_from_offset'),
    (8, 'get_qword_from_data', 'get_qword_from_offset'),
))
def test_negative_scalar_offsets_are_not_python_reverse_indexes(width, data_method, file_method):
    data = bytes(range(width * 2))
    from_data = getattr(reader.PE, data_method)
    assert from_data(data, 0) == int.from_bytes(data[:width], 'little')
    assert from_data(data, 1) == int.from_bytes(data[width:], 'little')
    assert from_data(data, 2) is None
    assert from_data(data, -1) is None
    assert from_data(data, -2) is None
    pe = image(fast_load=True)
    from_file = getattr(pe, file_method)
    assert from_file(0) == int.from_bytes(quarry_PE_32[:width], 'little')
    assert from_file(len(quarry_PE_32) - width + 1) is None
    assert from_file(-1) is None


@pytest.mark.parametrize(('width', 'data_method', 'file_method'), (
    (2, 'get_word_from_data', 'get_word_from_offset'),
    (4, 'get_dword_from_data', 'get_dword_from_offset'),
    (8, 'get_qword_from_data', 'get_qword_from_offset'),
))
def test_negative_int_subclass_offsets_are_rejected(width, data_method, file_method):
    class NegativeIndex(int):
        pass
    data = bytes(range(width * 2))
    assert getattr(reader.PE, data_method)(data, NegativeIndex(-2)) is None
    pe = image(fast_load=True)
    assert getattr(pe, file_method)(NegativeIndex(-2)) is None


def test_directory_request_list_keeps_only_absent_entries():
    pe = image(fast_load=True)
    assert [pe.OPTIONAL_HEADER.DATA_DIRECTORY[index].VirtualAddress for index in (0, 1, 6)] == [496, 0, 464]
    requested = [0, 1, 6]
    pe.parse_data_directories(requested)
    assert requested == [1]
    assert hasattr(pe, 'DIRECTORY_ENTRY_EXPORT')


def test_directory_request_list_removes_duplicate_present_indexes():
    pe = image(fast_load=True)
    requested = [0, 0, 1, 6, 6]
    pe.parse_data_directories(requested)
    assert requested == [1]


def test_directory_request_names_do_not_trigger_wrong_type_removal():
    pe = image(fast_load=True)
    requested = ['IMAGE_DIRECTORY_ENTRY_EXPORT']
    pe.parse_data_directories(requested)
    assert requested == ['IMAGE_DIRECTORY_ENTRY_EXPORT']
    assert not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT')


def record(name='one', pattern='41 42', ep=True, section=False):
    return f'[{name}]\nsignature = {pattern}\nep_only = {str(ep).lower()}\nsection_start_only = {str(section).lower()}\n'


@pytest.mark.parametrize('raw',[quarry_PE_32, quarry_PE_64])
def test_snapshot_and_ordinary_roundtrip(raw, tmp_path):
    supplied=bytearray(raw);pe=image(supplied);supplied[0]=0
    assert pe.__data__[0] == ord('M')
    before=bytes(pe.__data__)
    assert pe.set_bytes_at_offset(len(before)-1,b'X') is True
    assert len(pe.__data__) == len(before)
    result=pe.write();assert len(result)==len(before)
    output=tmp_path/'out.pe';assert pe.write(output) is None
    assert output.read_bytes()==result
    assert output.stat().st_mode & 0o777 == 0o600
    output.write_bytes(b'old');pe.write(output);assert output.read_bytes()==result
    source=tmp_path/'source.pe';source.write_bytes(raw)
    sourced=reader.PE(source);source.write_bytes(b'changed')
    assert sourced.write()==raw
    sourced.close();assert not hasattr(sourced,'__data__')


@pytest.mark.parametrize('offset,size', [(-1,1),(0,100000),(100000,1),(True,1),(1.5,1)])
def test_setter_rejects_outside_span(offset,size):
    pe=image();old=bytes(pe.__data__)
    assert pe.set_bytes_at_offset(offset,b'A'*size) is False
    assert bytes(pe.__data__)==old
    with pytest.raises(reader.PEFormatError): pe.set_data_bytes(offset,b'A'*size)
    assert bytes(pe.__data__)==old


def test_zero_offset_and_empty_end_edit():
    pe=image();assert pe.set_bytes_at_rva(0,b'MZ') is True
    assert pe.set_bytes_at_offset(len(pe.__data__),b'') is True
    assert pe.set_bytes_at_offset(len(pe.__data__),b'X') is False


@pytest.mark.parametrize('kind',['str','int','list'])
def test_memory_input_type(kind):
    with pytest.raises(TypeError): image({'str':'MZ','int':123,'list':[77,90]}[kind])


@pytest.mark.parametrize('option',['max_input_size','max_mapped_size'])
@pytest.mark.parametrize('value',[0,-1,True,1.5])
def test_invalid_limits(option,value):
    with pytest.raises(ValueError): image(**{option:value})


def test_input_limits_before_snapshot(tmp_path):
    with pytest.raises(quarry_LimitError): image(max_input_size=16)
    with pytest.raises(quarry_LimitError): image(memoryview(quarry_PE_32),max_input_size=16)
    path=tmp_path/'pe';path.write_bytes(quarry_PE_32)
    with pytest.raises(quarry_LimitError): reader.PE(path,max_input_size=16)
    assert path.read_bytes()==quarry_PE_32


@pytest.mark.parametrize('kind',['symlink','fifo','directory'])
def test_paths_do_not_block_or_follow(kind,tmp_path):
    target=tmp_path/'target';target.write_bytes(quarry_PE_32)
    path=tmp_path/'candidate'
    if kind=='symlink':path.symlink_to(target)
    elif kind=='fifo':os.mkfifo(path)
    else:path.mkdir()
    script='from pequarry.image_reader import PE;PE(__import__("sys").argv[1])'
    result=subprocess.run([sys.executable,'-c',script,str(path)],capture_output=True,timeout=3)
    assert result.returncode != 0
    pe=image()
    with pytest.raises((ValueError,OSError)):pe.write(path)
    assert target.read_bytes()==quarry_PE_32


def test_detectable_file_change(tmp_path,monkeypatch):
    path=tmp_path/'text';path.write_bytes(b'AB')
    real_read=os.read;changed=False
    def modified_read(fd,count):
        nonlocal changed
        data=real_read(fd,count)
        if not changed:path.write_bytes(b'CD');changed=True
        return data
    monkeypatch.setattr(os,'read',modified_read)
    with pytest.raises(ValueError,match='changed'):quarry_read_regular(path,8)


@pytest.mark.parametrize('offset',[-1,100000,True])
def test_serialization_offset_fails_before_output(offset,tmp_path):
    pe=image();pe.__structures__[0].set_file_offset(offset)
    out=tmp_path/'out';out.write_bytes(b'preserve')
    with pytest.raises(reader.PEFormatError):pe.write(out)
    assert out.read_bytes()==b'preserve'


def test_version_unicode_edit_keeps_size():
    pe=image();pe.VS_VERSIONINFO=object()
    table=SimpleNamespace(entries={b'key':'é'.encode()},entries_offsets={b'key':(0,128)},entries_lengths={b'key':(0,1)})
    pe.FileInfo=[[SimpleNamespace(StringTable=[table])]]
    raw=pe.write();assert len(raw)==len(quarry_PE_32)
    assert raw[128:130] == 'é'.encode('utf-16le')
    table.entries_offsets[b'key']=(0,-1)
    with pytest.raises(reader.PEFormatError):pe.write()


@pytest.mark.parametrize('virtual_size',[0xffffffff,0x10000000,0x10001])
def test_huge_mapped_section_fails_before_allocation(virtual_size):
    pe=image(max_mapped_size=65536)
    pe.sections[0].Misc_VirtualSize=virtual_size
    with pytest.raises(quarry_LimitError):pe.get_memory_mapped_image()


def test_mapping_preserves_overlap_rules():
    pe=object.__new__(reader.PE)
    pe._quarry_mapped_limit=64;pe.__data__=b'abcdefgh'
    pe.header=b'HEAD'
    pe.OPTIONAL_HEADER=SimpleNamespace(SectionAlignment=1,FileAlignment=1)
    pe.adjust_PointerToRawData=lambda value:value
    pe.adjust_SectionAlignment=lambda value,a,b:value
    def section(start,rva,size,data):
        return SimpleNamespace(SizeOfRawData=size,Misc_VirtualSize=size,PointerToRawData=start,VirtualAddress=rva,get_data=lambda:data)
    pe.sections=[section(0,8,4,b'abcd'),section(4,6,2,b'ef')]
    assert pe.get_memory_mapped_image()==b'HEAD\0\0ef'
    pe.sections[0].Misc_VirtualSize=100
    with pytest.raises(quarry_LimitError):pe.get_memory_mapped_image()


def test_default_signature_loading_never_network(tmp_path,monkeypatch):
    monkeypatch.setattr(signatures.quarry_request,'urlopen',lambda *a,**k:pytest.fail('implicit network'))
    monkeypatch.setattr(signatures.quarry_request,'build_opener',lambda *a,**k:pytest.fail('implicit network'))
    with pytest.raises(FileNotFoundError):signatures.SignatureDatabase(tmp_path/'missing')
    with pytest.raises(FileNotFoundError):signatures.SignatureDatabase('https://example.invalid/sig')
    db=signatures.SignatureDatabase(data=record())
    assert db.match_data(b'ABC') == (0,[['one']])


@pytest.mark.parametrize('bad',[
    '[x]\nsignature = FF\n', '[x]\nsignature = GG\nep_only = true\n',
    record(pattern='F'),record(pattern='???'),record(pattern='F?'),record(pattern=''),
    record().replace('true','yes'),record()+'unknown = x\n',record()+'ep_only = false\n',
    '[??]\nsignature = 41\nep_only = true\n', '[x]\nsignature = 41\nep_only = true\n[x\ny]\nsignature = 42\nep_only = true\n',
])
def test_signature_parse_is_atomic(bad):
    db=signatures.SignatureDatabase(data=record())
    count=db.signature_count_eponly_true;nodes=db._quarry_nodes
    with pytest.raises(ValueError):db.load(data=record(name='would-add')+bad)
    assert db.signature_count_eponly_true==count and db._quarry_nodes==nodes
    assert db.match_data(b'AB')==(0,[['one']])


@pytest.mark.parametrize('option,value,text',[
    ('max_bytes',8,record()),('max_signatures',1,record()+record('two')),
    ('max_depth',1,record()),('max_nodes',1,record()),
])
def test_signature_load_limits(option,value,text):
    with pytest.raises(quarry_LimitError):signatures.SignatureDatabase(data=text,**{option:value})


def test_signature_combine_and_terminal_wildcards():
    db=signatures.SignatureDatabase(data=record('first','41 ??'))
    assert db.match_data(b'A')==[]
    assert db.match_data(b'AB')==(0,[['first']])
    db.load(data=record('exact','41 42'))
    assert db.match_data(b'AB')==(0,[['first'],['exact']])
    assert db.match_data(b'AC')==(0,[['first']])
    db.load(data=record('whole','41',False))
    assert db.match_data(b'AB',ep_only=False)==[(0,[['whole']])]
    db.load(data=record('section','41',False,True))
    assert db.match_data(b'AB',ep_only=False,section_start_only=True)==[(0,[['section']])]


def test_long_signature_does_not_recurse():
    db=signatures.SignatureDatabase(data=record('long',' '.join(['41']*1500)))
    assert db.match_data(b'A'*1500)==(0,[['long']])
    assert db.match_data(b'A'*1499)==[]


def test_match_budgets_never_return_negative_result():
    db=signatures.SignatureDatabase(data=record(),max_match_steps=2)
    with pytest.raises(quarry_LimitError):db.match_data(b'AB')
    db=signatures.SignatureDatabase(data=record('a','41')+record('b','41'),max_matches=1)
    with pytest.raises(quarry_LimitError):db.match_data(b'A')
    db=signatures.SignatureDatabase(data=record('a','41',False),max_match_steps=16)
    fake=SimpleNamespace(__data__=b'A'*17)
    with pytest.raises(quarry_LimitError):db.match_all(fake,ep_only=False)


@pytest.mark.parametrize('url',['file:///tmp/x','http://example.invalid','https://a:b@example.invalid/x','https://example.invalid/#x','https://example.invalid/\n'])
def test_explicit_download_rejects_invalid_destinations(url,monkeypatch):
    monkeypatch.setattr(signatures.quarry_request,'build_opener',lambda *a,**k:pytest.fail('network before validation'))
    with pytest.raises(ValueError):signatures.SignatureDatabase().load_url(url)


def test_explicit_download_is_bounded(monkeypatch):
    class Response:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,count):return b'A'*count
    class Opener:
        def open(self,*args,**kwargs):return Response()
    monkeypatch.setattr(signatures.quarry_request,'build_opener',lambda *args:Opener())
    db=signatures.SignatureDatabase(max_bytes=32)
    with pytest.raises(quarry_LimitError):db.load_url('https://example.invalid/signatures')
    assert db.signature_count_eponly_true==0


def test_signature_generation_python3_and_span():
    pe=image();db=signatures.SignatureDatabase()
    text=db.generate_ep_signature(pe,'owned',sig_length=4)
    generated=signatures.SignatureDatabase(data=text)
    expected=pe.__data__[pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint):][:4]
    assert generated.match_data(expected)==(0,[['owned']])
    assert 'Section(' in db.generate_section_signatures(pe,'owned',sig_length=4)
    with pytest.raises(ValueError):db.generate_ep_signature(pe,'injected\n[other]',sig_length=4)


@pytest.mark.parametrize('seed',range(48))
def test_owned_header_mutations_are_finite(seed):
    rng=random.Random(seed);raw=bytearray(quarry_PE_32)
    for _ in range(8):raw[rng.randrange(min(512,len(raw)))]=rng.randrange(256)
    digest=hashlib.sha256(raw).digest()
    try:
        pe=image(raw,fast_load=True,max_input_size=65536,max_mapped_size=65536)
        try:pe.get_memory_mapped_image()
        except (reader.PEFormatError,quarry_LimitError):pass
        pe.close()
    except (reader.PEFormatError,quarry_LimitError):pass
    assert hashlib.sha256(raw).digest()==digest


def test_structure_budget_is_cumulative():
    with pytest.raises(quarry_LimitError,match='structure budget'):image(max_structures=1)
    pe=image(fast_load=True)
    pe._quarry_structure_limit=pe._quarry_structure_count+1
    pe.__unpack_data__(('OWNED',('I,Value',)),b'\0'*4,0)
    with pytest.raises(quarry_LimitError,match='structure budget'):
        pe.__unpack_data__(('OWNED',('I,Value',)),b'\0'*4,0)


def test_data_read_budget_is_cumulative():
    pe=image(fast_load=True,max_data_reads=1)
    assert pe.get_data(0,2)==b'MZ'
    with pytest.raises(quarry_LimitError,match='read budget'):pe.get_data(0,2)


@pytest.mark.parametrize('rva,length',[(-1,1),(0,-1),(True,1),(0,True),(0,1.5)])
def test_data_span_type_and_sign(rva,length):
    with pytest.raises(reader.PEFormatError):image(fast_load=True).get_data(rva,length)


def test_mapping_failed_relocation_restores_raw_mutable_bytes():
    pe=image();pe.set_bytes_at_offset(len(pe.__data__)-1,b'A')
    before=bytes(pe.__data__);original=pe.__data__
    def broken_relocation(base):
        pe.__data__[0]=0
        raise ValueError('owned relocation failure')
    pe.relocate_image=broken_relocation
    with pytest.raises(ValueError,match='owned relocation failure'):
        pe.get_memory_mapped_image(ImageBase=0x500000)
    assert pe.__data__ is original and bytes(pe.__data__)==before


def test_entrypoint_match_does_not_charge_unused_image_bytes():
    db=signatures.SignatureDatabase(data=record(),max_match_steps=4)
    pe=SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=2),get_memory_mapped_image=lambda:b'ZZAB'+bytes(100))
    assert db.match_all(pe)==[['one']]


def test_zero_relocation_padding_never_requests_negative_length():
    pe=image(fast_load=True)
    section=pe.sections[0]
    pe.set_data_bytes(section.PointerToRawData,b'\0'*8)
    warnings=pe.get_warnings()
    blocks=pe.parse_image_base_relocation_list(section.VirtualAddress,8)
    assert len(blocks)==1 and blocks[0].entries==[]
    assert pe.get_warnings()==warnings


def test_generated_section_signature_output_is_bounded():
    pe=image();db=signatures.SignatureDatabase(max_bytes=8)
    with pytest.raises(quarry_LimitError,match='generated signatures'):db.generate_section_signatures(pe,'owned',sig_length=4)


def test_rejected_redirect_closes_response(monkeypatch):
    captured=[]
    def inspect_opener(handler):
        captured.append(handler())
        return SimpleNamespace(open=lambda *args,**kwargs: (_ for _ in ()).throw(ValueError('owned stop')))
    monkeypatch.setattr(signatures.quarry_request,'build_opener',inspect_opener)
    with pytest.raises(ValueError,match='owned stop'):signatures.SignatureDatabase().load_url('https://example.invalid/sig')
    closed=[];response=SimpleNamespace(close=lambda:closed.append(True))
    with pytest.raises(ValueError,match='redirects'):
        captured[0].redirect_request(None,response,302,'redirect',{},'https://example.invalid/next')
    assert closed==[True]


@pytest.mark.parametrize('kind',['wide','signed','strided','multidimensional'])
def test_memoryview_signature_uses_raw_byte_semantics(kind):
    from array import array
    views={
        'wide':memoryview(array('I',[0x4241])),
        'signed':memoryview(array('b',[-1,65])),
        'strided':memoryview(b'AxB')[::2],
        'multidimensional':memoryview(b'ABCD').cast('B',shape=[2,2]),
    }
    view=views[kind];raw=bytes(view)
    db=signatures.SignatureDatabase(data=record('raw',' '.join(f'{byte:02x}' for byte in raw)))
    assert db.match_data(raw)==(0,[['raw']])
    assert db.match_data(view)==db.match_data(raw)


def test_memoryview_nbytes_limit_checked_before_snapshot():
    from array import array
    view=memoryview(array('I',[0])*2097153)
    assert len(view)<8*1024*1024 and view.nbytes>8*1024*1024
    with pytest.raises(quarry_LimitError,match='match input'):
        signatures.SignatureDatabase().match_data(view)


def test_missing_output_race_never_overwrites_new_file(tmp_path,monkeypatch):
    path=tmp_path/'output';real_open=os.open
    def concurrent_create(filename,flags,mode=0o777):
        if filename==path:
            path.write_bytes(b'other writer')
            assert flags & os.O_EXCL
        return real_open(filename,flags,mode)
    monkeypatch.setattr(os,'open',concurrent_create)
    with pytest.raises(FileExistsError):image().write(path)
    assert path.read_bytes()==b'other writer'


def test_regular_io_selects_binary_flag_when_available(tmp_path,monkeypatch):
    from pequarry.bounded_io import quarry_write_regular
    marker=1<<29;real_open=os.open;seen=[]
    monkeypatch.setattr(os,'O_BINARY',marker,raising=False)
    def inspect_open(filename,flags,mode=0o777):
        seen.append(flags)
        assert flags & marker
        return real_open(filename,flags & ~marker,mode)
    monkeypatch.setattr(os,'open',inspect_open)
    path=tmp_path/'bytes';data=b'A\r\n\x1aB'
    quarry_write_regular(path,data)
    assert quarry_read_regular(path,32)==data
    assert len(seen)==2
