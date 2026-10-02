from pathlib import Path
import json,hashlib,sys,importlib,struct
r=importlib.import_module(sys.argv[1]);data=Path(sys.argv[2]);observations=[]
paths=sorted(p for p in data.rglob('*') if p.is_file() and p.suffix.lower() not in ('.dmp','.about','.txt','.md','.py','.asm','.c','.h','.json','.yml','.yaml','.pdf','.png','.svg'))
for p in paths:
 raw=p.read_bytes();item={'file':str(p.relative_to(data)),'input_sha256':hashlib.sha256(raw).hexdigest()}
 try:
  pe=r.PE(data=raw)
  item.update(machine=pe.FILE_HEADER.Machine,pe_type=pe.PE_TYPE,section_count=len(pe.sections),entry=pe.OPTIONAL_HEADER.AddressOfEntryPoint,warnings=pe.get_warnings(),dump_info_sha256=hashlib.sha256(pe.dump_info().encode()).hexdigest(),dump_dict_sha256=hashlib.sha256(json.dumps(pe.dump_dict(),sort_keys=True,default=str).encode()).hexdigest(),write_sha256=hashlib.sha256(pe.write()).hexdigest(),checksum=pe.generate_checksum(),imphash=pe.get_imphash(),exports=pe.get_exphash())
  pe.close()
 except Exception as e:item.update(error_type=type(e).__name__.removeprefix('quarry_'),error_args=str(e.args))
 observations.append(item)
for size in [0,1,2,63,64,65,127,128,256,4096]:
 raw=b'MZ'+bytes(max(0,size-2)) if size else b''
 try: r.PE(data=raw);item={'size':size,'error':'none'}
 except Exception as e:item={'size':size,'error_type':type(e).__name__.removeprefix('quarry_'),'error_args':str(e.args)}
 observations.append(item)
print(json.dumps(observations,sort_keys=True))
