"""Repeat the lexical implementation-name audit of the mapped upstream files."""
from pathlib import Path as NamingPath
import hashlib as naming_hashlib
import json as naming_json
import libcst as naming_cst
from libcst.metadata import MetadataWrapper as NamingWrapper, ScopeProvider as NamingScopes
from libcst.metadata.scope_provider import FunctionScope as NamingFunction, ComprehensionScope as NamingComprehension, GlobalScope as NamingGlobal

naming_root = NamingPath(__file__).resolve().parents[1]
naming_record = naming_json.loads((naming_root/'NAME_AUDIT.json').read_text())
naming_prefix = {'GadgetHarbor':'harbor','PEQuarry':'quarry','IDBMeadow':'meadow'}[naming_record['project']]
naming_unrenamed = []
naming_global_contracts = {}
for naming_relative, naming_digest in naming_record['owned_python_source_sha256'].items():
    naming_source = (naming_root/naming_relative).read_bytes()
    assert naming_hashlib.sha256(naming_source).hexdigest() == naming_digest, naming_relative
    naming_wrapper = NamingWrapper(naming_cst.parse_module(naming_source.decode()))
    naming_scopes = naming_wrapper.resolve(NamingScopes)
    for naming_scope in set(naming_scopes.values()):
        for naming_assignment in naming_scope.assignments:
            naming_value = naming_assignment.name
            if naming_value.startswith((naming_prefix+'_','_name_boundary','_boundary_','boundary_','__')) or '.' in naming_value:
                continue
            if isinstance(naming_scope,(NamingFunction,NamingComprehension)):
                naming_unrenamed.append((naming_relative,naming_value))
            elif isinstance(naming_scope,NamingGlobal):
                naming_global_contracts.setdefault(naming_relative,set()).add(naming_value)
assert not naming_unrenamed, naming_unrenamed
assert {naming_relative:sorted(naming_values) for naming_relative,naming_values in naming_global_contracts.items()} == naming_record['fixed_global_contract_bindings']
print(naming_json.dumps({'status':'PASS','ordinary_unrenamed_function_or_comprehension_bindings':0,'mapped_owned_python_files':len(naming_record['owned_python_source_sha256'])}))
