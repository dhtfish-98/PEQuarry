# Validation

## Current 1.0.1 checks, 2026-10-02

Recorded environment: macOS Apple Silicon, Python 3.12.13.

- PASS: 127 project checks (2 retained embedded export cases and 125 new finite-input/edit/signature cases).
- PASS: 366 tests from the fixed public pefile-tests repository against the maintained runtime. The verifier also repeats the 366 upstream control tests.
- PASS: all 373 existing PE observations equal the frozen upstream: headers, warnings, dumps, serialization, checksum, imports/exports and malformed-input outcomes.
- PASS: all 1,204 additional ordinary signature observations equal the frozen upstream, including internal wildcards and partial data. This ordinary corpus deliberately ends patterns in concrete bytes; terminal-wildcard error changes have separate expected-result tests.
- Covered changes include file/input/output spans, nonblocking rejection of final links/FIFOs/devices, detectable file mutation, owned memory snapshots, mapping total-size planning, cumulative structure/read budgets, offset-zero edits, version-string size preservation, mutable raw-byte recovery on failed relocation, iterative 1,500-byte signatures, atomic malformed loads, count/depth/node/match budgets and explicit-download validation. Mocked download tests make no outbound request.
- Deterministic mutation checks use 48 altered copies of owned embedded header bytes. They cover those finite cases and do not establish arbitrary malformed-input safety.

The current verifier builds source and wheel distributions, checks every runtime Python byte and provenance document, installs the wheel into a fresh environment and checks installed identity, PE32/64 parse/exports/write/checksum, terminal wildcards and an input limit. A successful verifier run records the measured package consumption in `.verification/result.json`. Remote CI and release asset hashes are separate evidence tied to their actual Git commit; they are not inferred from this document.

## Scope and remaining work

- OPEN: retained directory parsing, resource/version interpretation, relocation semantics, unwind/structure helpers, alias machinery and dump formatting are not all independently rewritten. Cumulative read/structure counters bound those mediated operations; they do not bound every direct-slice loop, total memory, CPU time or text output.
- OPEN: no PE sample was executed; Windows loading, arbitrary malformed inputs and runtime behavior remain unmeasured. A static mapped image is not proof of loader fidelity.
- OPEN: new output is deliberately non-atomic; an explicit existing regular file may be overwritten. A failed write may leave a partial output. Existing file permissions are retained; new output gets mode 0600.
- OPEN: socket timeout is not a complete elapsed-time bound; caller-provided custom objects and changed library settings have not been universally validated.
- OPEN: Python 3.10/3.11 and Windows host behavior have not been measured in this local run. CI uses Linux Python 3.12.
- OPEN: public sample origins are mixed/partly undocumented. The fixed sample checkout is used only for comparison and is not redistributed.

## Historical 1.0.0 evidence

The previous release recorded 366 control/runtime tests and 373 equal PE observations after naming/module reorganization. Its immutable assets remain historical artifacts and do not contain the 1.0.1 boundary rewrite.

The upstream encrypted test_data archive is unavailable. Its old 26-test regression run produced 12 passes and 14 failures against available replacement samples. A repeatable 23-case subset reports 10 passes and 13 identical baseline fixture failures; the remaining control-generating test was not repeated. These are retained in `historical_checks`; they are not reported as a passing 26-case gate.

The earlier lexical naming audit covered 10 mapped source/test files and 1,777 historical binding records. Current byte hashes cover the current files; the newly written signature module is explicitly recorded as a readable rewrite rather than being presented as another automatic rename. Naming is not security evidence.

No test count, build, repository quantity or GitHub workflow proves CVP approval, applicant identity, organizational authorization, sample safety or independent authorship.
