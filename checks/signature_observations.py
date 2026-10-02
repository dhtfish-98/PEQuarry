import importlib,sys,json,random
m=importlib.import_module(sys.argv[1]);cases=[]
rng=random.Random(9381)
for i in range(128):
    tokens=['??' if rng.randrange(4)==0 else f'{rng.randrange(256):02x}' for _ in range(rng.randrange(1,16))]
    tokens[-1]=f'{rng.randrange(256):02x}'
    data=bytes(rng.randrange(256) if t=='??' else int(t,16) for t in tokens)
    text=f'[sig-{i}]\nsignature = {" ".join(tokens)}\nep_only = true\n'
    db=m.SignatureDatabase(data=text)
    for size in range(len(data)+2):
        candidate=(data+b'Z')[:size]
        cases.append({'case':i,'size':size,'result':db.match_data(candidate),'count':db.signature_count_eponly_true,'depth':db.max_depth})
print(json.dumps(cases,sort_keys=True))
