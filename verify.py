#!/usr/bin/env python3
"""Audit frozen source, repeat upstream comparisons, and build installable artifacts."""
from pathlib import Path
import argparse,hashlib,importlib.metadata,json,os,subprocess,sys,tempfile,zipfile,tarfile
ROOT=Path(__file__).resolve().parent
CONFIG={'name': 'PEQuarry', 'upstream': 'https://github.com/erocarrera/pefile.git', 'commit': 'e521f469b41abb074bae1cc0820396d6f7663cd9'}
WORK=ROOT/'.verification'

def run(command,**kwargs):
    print('+',' '.join(map(str,command)),flush=True)
    return subprocess.run(list(map(str,command)),cwd=ROOT,check=True,**kwargs)

def checkout(url,commit,name):
    path=WORK/name
    if not path.exists():run(['git','clone','--quiet',url,path])
    actual=subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip()
    if actual!=commit:run(['git','-C',path,'checkout','--quiet','--detach',commit])
    assert subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip()==commit
    return path

def source_audit():
    manifest=json.loads((ROOT/'SOURCE_MANIFEST.json').read_text())
    for relative,record in manifest['files'].items():
        p=ROOT/relative
        assert hashlib.sha256(p.read_bytes()).hexdigest()==record['sha256'],relative
        assert bool(p.stat().st_mode&0o111)==bool(record['executable']),relative+' mode differs'
    return len(manifest['files'])

def compare_observations(script,original_modules,new_modules,dataset,baseline):
    env=dict(os.environ,PYTHONPATH=str(baseline))
    inputs=[] if dataset is None else [dataset]
    first=run([sys.executable,ROOT/'checks'/script,*original_modules,*inputs],capture_output=True,env=env).stdout
    second=run([sys.executable,ROOT/'checks'/script,*new_modules,*inputs],capture_output=True).stdout
    old=json.loads(first);new=json.loads(second)
    if script=='pe_observations.py':
        from checks.known_pe_changes import compare
        return compare(old,new,baseline,dataset)
    assert old==new,'Original and rewritten observations differ'
    return len(old)

def clear_generated_build(root):
    # On case-insensitive filesystems, root/'build' can refer to root/'Build'.
    # Only remove an actual directory entry with the exact generated name.
    with os.scandir(root) as entries:
        for entry in entries:
            if entry.name != 'build':
                continue
            if entry.is_symlink():
                raise ValueError('Refusing to remove symlink: '+entry.path)
            if not entry.is_dir(follow_symlinks=False):
                raise ValueError('Refusing to remove non-directory: '+entry.path)
            import shutil
            shutil.rmtree(entry.path)
            return

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--audit-only',action='store_true')
    parser.add_argument('--baseline',type=Path)
    parser.add_argument('--pe-tests',type=Path)
    parser.add_argument('--runslow',action='store_true')
    parser.add_argument('--skip-tests',action='store_true',help='Repeat differences/build after a separately recorded complete suite; does not claim tests ran.')
    args=parser.parse_args()
    WORK.mkdir(exist_ok=True)
    checks={'project':CONFIG['name'],'source_files_verified':source_audit(),'status':'PASS'}
    if args.audit_only:
        print(json.dumps(checks));return
    checks['lexical_naming_audit']=json.loads(run([sys.executable,ROOT/'checks/naming_audit.py'],capture_output=True).stdout)
    baseline=args.baseline.resolve() if args.baseline else checkout(CONFIG['upstream'],CONFIG['commit'],'upstream')
    name=CONFIG['name']
    if name=='GadgetHarbor':
        run([sys.executable,ROOT/'checks/gadget_probe.py',baseline])
        checks['static_cli_differences']=json.loads((WORK/'GadgetHarbor-differential.json').read_text())['case_count']
    elif name=='PEQuarry':
        suite=args.pe_tests.resolve() if args.pe_tests else checkout('https://github.com/erocarrera/pefile-tests.git','7fb3461fda128b4f7864c0891e03babbe43f6d9b','pe-tests')
        if not args.skip_tests:
            run([sys.executable,'-m','pytest','checks','-q','-p','no:cacheprovider'])
            env=dict(os.environ,PYTHONPATH=str(baseline))
            run([sys.executable,'-m','pytest',suite/'tests','-q'],env=env)
            run([sys.executable,ROOT/'checks/maintained_suite.py',suite/'tests'])
        checks['file_and_error_differences']=compare_observations('pe_observations.py',['pefile'],['pequarry.image_reader'],suite/'tests',baseline)
        original_signature=run([sys.executable,ROOT/'checks/signature_observations.py','peutils'],capture_output=True,env=dict(os.environ,PYTHONPATH=str(baseline))).stdout
        current_signature=run([sys.executable,ROOT/'checks/signature_observations.py','pequarry.signature_tools'],capture_output=True).stdout
        assert json.loads(original_signature)==json.loads(current_signature),'Bounded ordinary signature observations differ'
        checks['ordinary_signature_observations_equal']=len(json.loads(current_signature))
        checks['normal_directory_observations_equal']=compare_observations('directory_observations.py',['pefile'],['pequarry.image_reader'],None,baseline)
        checks['normal_resource_observations_equal']=compare_observations('resource_observations.py',['pefile'],['pequarry.image_reader'],None,baseline)
        original_history=run([sys.executable,ROOT/'checks/legacy_pe_observations.py',baseline/'tests/pefile_test.py',suite/'tests/data','original'],capture_output=True,env=dict(os.environ,PYTHONPATH=str(baseline))).stdout
        rewritten_history=run([sys.executable,ROOT/'checks/legacy_pe_observations.py',ROOT/'historical_checks/legacy_quarry_regression.py',suite/'tests/data','rewritten'],capture_output=True).stdout
        original_history=json.loads(original_history);rewritten_history=json.loads(rewritten_history)
        assert original_history==rewritten_history,'Historical PE outcomes differ'
        checks['historical_outcomes_equal']=len(original_history)
        checks['historical_cases_passed_each']=sum(item['outcome']=='PASS' for item in original_history)
        checks['historical_fixture_failures_identical_each']=sum(item['outcome']=='BASELINE_FAILURE' for item in original_history)
    else:
        if not args.skip_tests:
            flags=['--runslow'] if args.runslow else []
            run([sys.executable,'-m','pytest','checks','-q',*flags])
        checks['database_and_error_differences']=compare_observations('idb_observations.py',['idb','idb.analysis'],['idbmeadow','idbmeadow.semantic_views'],ROOT/'checks/data',baseline)
    # Remove only generated build output, so a prior cached copy cannot lose modes.
    clear_generated_build(ROOT)
    # Build both directly from this tree: frontend sdist extraction normalizes modes.
    # Keep earlier generated versions separate from the current artifact gate.
    distribution_output=WORK/'dist'/json.loads((ROOT/'CURRENT_REVIEW.json').read_text())['version']
    run([sys.executable,'-m','build','--no-isolation','--sdist','--wheel','--outdir',distribution_output])
    wheels=list(distribution_output.glob('*.whl'));assert len(wheels)==1
    with zipfile.ZipFile(wheels[0]) as archive:
        for source in (ROOT/'src').rglob('*.py'):
            relative=str(source.relative_to(ROOT/'src'))
            assert archive.read(relative)==source.read_bytes(),'Wheel source differs: '+relative
        for document in ('README.md','ORIGIN.md','VALIDATION.md','DEFENSIVE_SCOPE.md','NAME_AUDIT.json','CURRENT_REVIEW.json','REVIEWED_VERSION_CHANGES.json'):
            members=[path for path in archive.namelist() if path.endswith('/share/'+CONFIG['name']+'/'+document)]
            assert len(members)==1 and archive.read(members[0])==(ROOT/document).read_bytes(),'Wheel provenance differs: '+document
    checks['wheel_source_identity']='PASS'
    sources=list(distribution_output.glob('*.tar.gz'));assert len(sources)==1
    with tarfile.open(sources[0]) as source_archive:
        source_members=source_archive.getmembers()
        for relative,record in json.loads((ROOT/'SOURCE_MANIFEST.json').read_text())['files'].items():
            members=[member for member in source_members if member.isfile() and member.name.endswith('/'+relative)]
            assert len(members)==1, 'Source distribution missing audit file: '+relative
            assert source_archive.extractfile(members[0]).read()==(ROOT/relative).read_bytes(), 'Source distribution bytes differ: '+relative
            assert bool(members[0].mode&0o111)==bool(record['executable']), 'Source distribution mode differs: '+relative
    checks['source_distribution_identity']='PASS'
    # A fresh environment ensures consumption cannot import this editable checkout.
    import venv
    with tempfile.TemporaryDirectory(prefix='wheel-consumption-') as consumer_directory:
        consumer=Path(consumer_directory)
        venv.EnvBuilder(with_pip=True).create(consumer)
        interpreter=consumer/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
        run([interpreter,'-I','-m','pip','install','--no-index','--no-deps','--force-reinstall','--disable-pip-version-check',wheels[0]])
        env=dict(os.environ,PYTHONPATH='')
        result=run([interpreter,'-I',ROOT/'checks/wheel_consumption.py',ROOT,CONFIG['name']],capture_output=True,env=env)
        checks['independent_wheel_consumer']=json.loads(result.stdout)
    (WORK/'result.json').write_text(json.dumps(checks,indent=2)+'\n')
    print(json.dumps(checks))

if __name__=='__main__':main()
