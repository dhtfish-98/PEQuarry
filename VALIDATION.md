# Validation

Recorded environment: macOS Apple Silicon, Python 3.12.13, Capstone 5.0.6, pytest 9.1.1. IDB dependencies: vivisect-vstruct-wb 1.0.3, six 1.17.0, cached-property 2.0.1, hexdump 3.3.

PASS: 2 embedded PE32/PE64 export tests; original and rewritten public pefile-tests suite, 366 tests each. PASS: 373 original/new file and malformed-input observations including dump_info/dump_dict hashes, emitted bytes, checksum, imports/exports and error type/message.

## Limits and pre-existing gaps

- OPEN: The upstream encrypted test_data archive is not usable. Its old 26-test regression suite produced 12 passes and 14 failures against the available replacement samples; these missing/mismatched historical fixtures are retained in historical_checks and excluded from the ordinary suite, not reported as passing.
- OPEN: The independent public sample repository has mixed/partly undocumented sample origins. It is checked out only for validation at a fixed commit and is not redistributed in this project.
- OPEN: No PE sample was executed; Windows loading, arbitrary malformed inputs and runtime behavior remain outside the measured static checks.

Local automated checks, installable-package consumption, source identity and remote GitHub workflow results are distinct evidence. Remote CI is not presumed from a local pass. No application/verification-program approval or independent authorship claim follows from these checks.

Additional PASS: 23 available historical test outcomes are equal between original and renamed sources: 10 passes and 13 identical fixture-related failures. The remaining control-generating regression test is not repeated; its original failure remains OPEN.

PASS: lexical name audit of 10 mapped owned Python files; 1777 binding-map records and zero ordinary unrenamed function/comprehension bindings. PASS: two independent wheel-consumer checks in a fresh temporary environment, with every installed Python source file compared byte-for-byte. NAME_AUDIT.json records the permitted fixed global contracts.
