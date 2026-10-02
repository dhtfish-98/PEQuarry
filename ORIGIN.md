# Origin

- Upstream: [pefile](https://github.com/erocarrera/pefile)
- Frozen commit: `e521f469b41abb074bae1cc0820396d6f7663cd9`
- Frozen tree: `09c20c3324bfafdf9592379ed6028f0fd36f48d3`
- License: MIT; complete original license, author notices and retained source headers are included.

This project derives from upstream code and does not claim its original algorithms as newly invented. The original source checkout was read-only. Renaming uses LibCST assignment/reference scope identities, including a guard against same-spelling local/global shadowing, followed by AST routing of known module/member identities. Owned source files/modules and custom implementation bindings are renamed; reusable mechanisms are separated from format/API labels in api_contract.py.

## Required compatibility exceptions

- Windows PE field names, directory/machine constants, DLL ordinal table bytes, codec error-handler name and serialization keys remain format contracts.
- The renamed source retains legacy public member aliases under the new pequarry modules. Mutable module settings such as MAX_SECTIONS remain routed to the renamed storage.
- Standard Python hooks and original copyright/header notices remain fixed.

PE validation dataset: [erocarrera/pefile-tests](https://github.com/erocarrera/pefile-tests), commit `7fb3461fda128b4f7864c0891e03babbe43f6d9b`. Its test code is BSD/MIT; its README explicitly records mixed/uncertain binary sample origins. These sample bytes remain in a separate validation checkout and are not included in this distribution.

Binary fixture filenames and bytes remain fixed comparison inputs. Required __init__.py, conftest.py, pyproject.toml and license filenames remain conventional tool/API contracts. Original executable modes and script shebang placement are preserved.

Ordinary local bindings are renamed even when their old spelling also appears in a fixed schema field. Scope-resolved local/global refinements are listed in SYMBOL_MAP.json. NAME_AUDIT.json and checks/naming_audit.py repeat the owned-source lexical audit.

Upstream packaging configuration is expressed in the new pyproject.toml. Distribution/module identity changes deliberately; parsing behavior, CLI flags and external data contracts are verified separately.
