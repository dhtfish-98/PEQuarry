# Validation

## Current 1.0.5 maintenance checks, 2026-10-05

Recorded environment: macOS Apple Silicon, Python 3.14.6. The 1.0.5 change is limited to unreachable shared verification branches, their source-manifest entries, version metadata and current documentation. All 14 PE runtime Python files are byte-identical to 1.0.4.

- PASS: 55 source-manifest files have matching bytes, hashes and modes; `verify.py --audit-only` and the lexical naming check pass in an isolated `Build` staging tree.
- PASS: the existing 319 project checks pass in that staging tree. These are routine regression checks, not the interrupted 12-project deep review.
- PASS: local 1.0.5 wheel and sdist build; all 55 tracked source files match the sdist, and all 14 runtime Python files match the wheel. The installed wheel consumer reports 14 identical runtime files and 10 passing offline operations.
- PASS: both local packages contain zero occurrences of the unrelated private project's name and retain the original pefile MIT license; no old stage 3 report was added. Historical Git commits and 1.0.4 assets still carry their original bytes.
- OPEN: exact-commit remote CI, final release assets and the unpublished old stage 3 have not been verified by these local checks. The system-interrupted full deep review remains incomplete.

## Historical 1.0.4 checks, 2026-10-04

Recorded environment: macOS Apple Silicon, Python 3.12.13.

- PASS: 319 project checks, including three new tests of exact-name generated `build` cleanup, `Build` staging preservation and symlink refusal.
- The PE runtime source and fixed upstream comparisons have the 1.0.3 scope recorded below. The conditional risk involved direct full verification from a root containing `Build` on a case-insensitive filesystem; deletion was not observed in the normal `Build/源码` or existing CI path. The new cleanup checks exercise a case-insensitive local filesystem; Linux CI can additionally exercise distinct `Build` and `build` entries. CI and release evidence must be tied to the actual 1.0.4 commit and artifacts.

## Historical 1.0.3 checks, 2026-10-02

Recorded environment: macOS Apple Silicon, Python 3.12.13.

- PASS: 316 project checks (2 retained embedded export cases, 125 input/edit/signature, 84 directory/unwind, 58 resource, 43 version and 4 observation-key cases).
- PASS with two precise reviewed source corrections: 364 maintained public tests and 2 strict expected legacy snapshot failures. The unmodified frozen source control has 366 passes. Each selected snapshot must have the exact frozen file SHA; missing/extra expected failures or unexpected passes fail the gate. Independent raw bytes and entire corrected dumps are verified separately, so these are not general case exclusions.
- PASS: 373 freshly comparable PE observations: 371 strictly identical; 2 precisely reviewed version corrections. All remaining fields, including warnings outside the two removed diagnostics, serialization, checksum and imports/exports, remain strictly identical. `REVIEWED_VERSION_CHANGES.json` preserves complete old/current dump text, typed version fields, observations and independent bounded byte decoding. Mixed byte/text dictionary keys are now encoded with their types; the previous observer raised TypeError on version_std and did not compare its downstream fields. Historical claims of 373 equal observation records included this identical observer error, not full dump equivalence for that sample.
- PASS: 149 additional synthetic normal relocation/dynamic/function-override/exception observations equal the frozen upstream, including bytes, record offsets, unwind dumps and serialization.
- PASS: 128 additional normal resource/version observations are strictly equal: metadata/physical offsets, Unicode names/strings, fixed version fields, string offsets/lengths and serialization.
- PASS: all 1,204 additional ordinary signature observations equal the frozen upstream, including internal wildcards and partial data. This ordinary corpus deliberately ends patterns in concrete bytes; terminal-wildcard error changes have separate expected-result tests.
- Covered changes include file/input/output spans, nonblocking rejection of final links/FIFOs/devices, detectable file mutation, owned memory snapshots, mapping total-size planning, cumulative structure/read budgets, offset-zero edits, version-string size preservation, mutable raw-byte recovery on failed relocation, iterative 1,500-byte signatures, atomic malformed loads, count/depth/node/match budgets and explicit-download validation. Mocked download tests make no outbound request.
- Deterministic mutation checks use 48 altered copies of owned embedded header bytes. They cover those finite cases and do not establish arbitrary malformed-input safety.

The current verifier builds source and wheel distributions, checks every runtime Python byte and provenance document, installs the wheel into a fresh environment and checks installed identity, PE32/64 parse/exports/write/checksum, terminal wildcards, input limits, function/BDD and runtime/unwind directories, a directory budget, resource metadata completion, multiple version tables and UTF-16 edit isolation. A successful verifier run records the measured package consumption in `.verification/result.json`. Remote CI and release asset hashes are separate evidence tied to their actual Git commit; they are not inferred from this document.

## Scope and remaining work

- OPEN: remaining import/export/debug/TLS/bound-import/load-config interpretation, relocation application, unwind opcode/optional-chain/IA64 semantics, structure helpers, alias machinery and dump formatting are not all independently rewritten. Cumulative read/structure counters bound those mediated operations; they do not bound every direct-slice loop, total memory, CPU time or text output.
- OPEN: no PE sample was executed; Windows loading, arbitrary malformed inputs and runtime behavior remain unmeasured. A static mapped image is not proof of loader fidelity.
- OPEN: new output is deliberately non-atomic; an explicit existing regular file may be overwritten. A failed write may leave a partial output. Existing file permissions are retained; new output gets mode 0600.
- OPEN: socket timeout is not a complete elapsed-time bound; caller-provided custom objects and changed library settings have not been universally validated.
- OPEN: Python 3.10/3.11 and Windows host behavior have not been measured in this local run. CI uses Linux Python 3.12.
- OPEN: public sample origins are mixed/partly undocumented. The fixed sample checkout is used only for comparison and is not redistributed.

## Historical 1.0.0 evidence

The previous release recorded 366 control/runtime tests and 373 equal PE observations after naming/module reorganization. Its immutable assets remain historical artifacts and do not contain the 1.0.1 boundary rewrite.

The upstream encrypted test_data archive is unavailable. Its old 26-test regression run produced 12 passes and 14 failures against available replacement samples. A repeatable 23-case subset reports 10 passes and 13 identical baseline fixture failures; the remaining control-generating test was not repeated. These are retained in `historical_checks`; they are not reported as a passing 26-case gate.

The earlier lexical naming audit covered 10 mapped source/test files and 1,777 historical binding records. Current byte hashes cover the current files; the newly written signature, directory, resource and version modules are explicitly recorded as a readable rewrite rather than being presented as another automatic rename. Naming is not security evidence.

No test count, build, repository quantity or GitHub workflow proves CVP approval, applicant identity, organizational authorization, sample safety or independent authorship.

## 1.0.2 directory changes and limits

The new finite traversal checks header/payload containment, block progress and alignment, selected-section extents, override RVA/BDD lengths, duplicate relocation entries, short raw spans and code operand slots before initialization. The record budget also counts non-structure override integers and unwind slots. Its default is 1,048,576: a 131,072-record trial stopped the valid FileZilla regression sample after counting its operand slots; this was a limit configuration failure, and the default was increased before publication. Smaller explicit limits remain tested.

The staged `UnwindInfo` API and existing field/result objects remain; the legacy optional FunctionEntry representation, opcode classes, relocation application and IA64 interpretation are not fully rewritten or loader-verified. This phase does not establish correct loader handling of every unwind encoding. Historical 1.0.1 release assets remain unchanged.

## 1.0.3 resource/version checks and exact corrections

Resource metadata uses an explicit active-path stack, per-record parent spans, unsigned bounded UTF-16 names and neighbor-checked name intervals. Zero-size metadata remains an unknown span for compatibility; actual reads and cumulative records/UTF-16 units still have limits. Partial/cyclic trees mark `metadata_complete=False`; partial RT_STRING cells mark `strings_complete=False`. A short but decodable final RT_STRING retains its actual text as incomplete evidence. These markers describe traversed scope, not full Windows semantic validity.

Version records use declared parent lengths, finite alignment/progress and separate String UTF-16-unit/Var byte lengths. Unicode edit capacity is measured independently of the compatible historical UTF-8 lengths. Optional Children/fixed values and multiple string tables/Var records have direct expected-result tests.

The [Microsoft VS_VERSIONINFO layout](https://learn.microsoft.com/en-us/windows/win32/menurc/vs-versioninfo) permits absent Children; [String](https://learn.microsoft.com/en-us/windows/win32/menurc/string-str) declares its value length in WORD units, while [Var](https://learn.microsoft.com/en-us/windows/win32/menurc/var-str) declares bytes. The independent decoder reads only raw `<HHH` headers, bounded UTF-16 cells and little-endian DWORD/WORD values. It invokes no maintained parser. The unchanged source formatter renders structures populated from that independent decoding; the entire current text/dict dump must equal this expected result.

- `version_cust.exe`, SHA-256 `60b50d9a03b2580a4ec8d7d3da230dc3f62ec5489ec81e15b690fb39a3c78a27`: root offset 600, length 92, fixed value 52 bytes, end 692. There are no Children. Exactly two spurious diagnostics about missing StringFileInfo are removed; every other dump field and original write byte remains identical.
- `version_std.exe`, SHA-256 `927081b2c9548694c85e46aa2c6d965fc43ed5121aa4d47fbcda3d990996a592`: root 600..1660; StringFileInfo 692..1592; table 728..1592 contains 17 records, producing 16 final keys with the last duplicate FileVersion retained. VarFileInfo 1592..1660 contains a 4-byte zero/zero language/codepage pair at 1656. The complete corrected version fields/offsets/text/dict output match independent bytes; all non-version fields and original write bytes remain identical. The unusual fixture text/duplicate keys are observations, not a claim of Windows acceptance.

Historical 1.0.0/1.0.1/1.0.2 asset bytes remain unchanged. They do not contain later stage code or the repaired observer. The resource/version stage is a finite rewrite, not completion of every remaining parser or overall CVP eligibility.
