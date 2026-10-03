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

## 1.0.1 boundary rewrite

The signature component is now a new line parser, atomic bounded trie loader and iterative matcher. New `bounded_io.py` owns finite regular-file operations. PE input, static mapped-image construction, serialization and checksum routines were rewritten; byte edits and mediated structure/data-read operations gained explicit limits. This is substantive maintenance of an attributed derivative. The remaining directory parsers, binary field tables, ordinal data and alias machinery retain substantial upstream/reorganization code and are not claimed as newly authored algorithms.

The current `SOURCE_MANIFEST.json` records current bytes. `SYMBOL_MAP.json`/`FILE_MAP.json` preserve the historical renaming provenance; they are not a declaration that newly written routines preserve every old local name. `NAME_AUDIT.json` explicitly excludes the readable signature rewrite from the historical lexical-name criterion while retaining its current source hash.

PE field/layout checks also refer to the [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format). That specification distinguishes file offsets from RVAs; it does not prove the complete Windows loader behavior of this implementation.

## 1.0.2 finite directory traversal

`directory_records.py` independently implements relocation and exception traversal, staged unwind slot containment and parent-bounded dynamic/function/BDD parsing. Windows schemas and public result objects remain attributed contracts; opcode classes, optional-chain representation, relocation application and IA64 interpretation retain upstream semantics and remain OPEN. `image_reader.py` exposes compatible API bridges to these routines. Historical naming maps remain historical; both readable rewritten components are source-hash checked.

The additional 149 normal directory comparisons use deterministic synthetic data within the attributed embedded PE headers; no new third-party binary corpus is redistributed. x64 field checks refer to [Microsoft x64 exception handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64), while this implementation still preserves legacy optional-field compatibility and does not claim complete loader equivalence.

## 1.0.3 resource/version traversal

`resource_records.py` and `version_records.py` are independently written finite readers using retained attributed schema/result classes and compatible API bridges. Resource traversal uses a stack, active cycles, metadata/UTF-16 extents and partial-scope markers. Version records use parent lengths, code-unit accounting and actual Unicode edit capacity. Import/export/debug/TLS/bound-import/load-config, relocation application, remaining opcode/structure/alias/formatter algorithms still retain substantial source code and remain OPEN.

The exact two source corrections preserve old actual results and independent byte evidence in `REVIEWED_VERSION_CHANGES.json`. Microsoft primary layouts: [VS_VERSIONINFO](https://learn.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo), [String](https://learn.microsoft.com/en-us/windows/win32/menurc/string-str), [Var](https://learn.microsoft.com/en-us/windows/win32/menurc/var-str). Those layouts support the field interpretation; they do not prove Windows acceptance of unusual corpus fixtures. The typed-key observation encoding fixes a comparison-tool TypeError, rather than treating an identical tool error as field equivalence. All immutable earlier asset bytes retain their historical scope.
