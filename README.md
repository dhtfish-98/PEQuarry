# PEQuarry

Bounded local PE inspection and static signature review, derived from [pefile](https://github.com/erocarrera/pefile). MIT attribution and the frozen upstream commit remain in [ORIGIN.md](ORIGIN.md).

Version 1.0.1 substantively rewrites the local input, mapped-image planning, serialization, checksum and signature-database components. Other attributed directory parsers, structure helpers, aliases and ordinal tables remain. This is an ongoing defensive maintenance project; it is not a claim that every upstream algorithm has been rewritten.

## Install and use

Python >=3.10; the recorded verification environment is Python 3.12.13. Python 3.10 execution has not been measured. The prior >=3.9 metadata was corrected because runtime annotations use Python 3.10 unions.

```python
from pequarry import image_reader, signature_tools

with image_reader.PE("authorized-local-sample.exe") as image:
    print(image.FILE_HEADER.Machine, len(image.sections))
    edited_bytes = image.write()  # Serialize bytes; does not execute the sample.

signatures = signature_tools.SignatureDatabase(data="""[owned]
signature = 41 ?? 43
ep_only = true
""")
print(signatures.match_data(b"ABC"))
```

## Boundaries and deliberate changes

- PE input: owned bytes from bytes/bytearray/memoryview or a regular local file. Default input and complete mapped-image limits are 256 MiB each. Final symbolic links, devices and FIFOs are rejected. Detectable identity/size/time changes during file reading fail; this is not a coherent forensic capture guarantee.
- PE parsing: default cumulative budgets of 131,072 structure decodes and 1,048,576 `get_data` calls. Existing resource/import/export limits remain. These counters do not prove every directory algorithm, direct data slice or formatting path is fully bounded.
- Mapping: `max_virtual_address` retains the upstream starting-RVA selection convention; `max_mapped_size` additionally bounds the entire result before padding allocation. Relocation still changes parsed structure fields by the upstream API contract; raw bytes are restored even on a failed relocation/mapping. Mapping does not reproduce a verified Windows loader.
- Editing: byte setters reject spans beyond the existing file and permit the valid offset zero. `write()` returns a bytearray and retains normal header edits and small padding extensions. Invalid offsets and output growth beyond the input limit fail. UTF-16 version edits cannot resize the file. An explicit output path can overwrite an existing regular file; it rejects final links/devices and creates new files exclusively with mode 0600. A path created concurrently after the missing-path check is not overwritten. Writes are not atomic.
- Signature loading: `filename` is only a local path, including when missing. `data` accepts text or UTF-8 bytes. Loads combine only after complete validation. Unknown/duplicate fields, invalid tokens/flags and malformed records fail instead of silently disappearing. Only complete two-digit hex tokens and `??` are supported.
- Signature defaults: 8 MiB combined input, 65,536 records, 4,096-byte patterns, 1,048,576 tree nodes, 4,194,304 matching steps and 65,536 matched names. Match inputs are snapshotted as raw bytes (including signed, multi-byte or strided memoryviews), with nbytes checked before copying. Matching is iterative. A budget failure raises `quarry_LimitError`; it is an incomplete operation, not a negative match.
- Full-length terminal wildcards now consume a byte; short data no longer becomes a match through trimmed terminal wildcards. `match_data(..., ep_only=False)` now selects the full-file tree instead of raising an uninitialized-variable error. Python 3 signature generation works on integer bytes and sanitizes section labels.
- Online retrieval is a separate explicit `signatures.load_url("https://authorized-host/signatures")` operation. It permits HTTPS without URL credentials/fragments, rejects redirects, caps bytes and uses a finite socket timeout. The caller owns destination authorization. Ordinary construction and `load()` make no request. Byte/socket limits are not a total wall-clock deadline.
- `is_valid` and `is_suspicious` remain upstream placeholders returning `None`; they are not verdicts. Entropy/signature observations do not establish maliciousness or trust.

## Verification

```sh
python -m pip install '.[test]'
python verify.py
```

The verifier checks the current source manifest, runs 127 project checks plus the fixed independent 366-test suite, compares 373 PE observations and 1,204 ordinary signature observations against the pinned upstream, and builds/consumes the wheel in a fresh environment. It separately retains the historical unavailable/mismatched fixture failures. No input PE is executed. `--baseline PATH` and `--pe-tests PATH` reuse the fixed source/test checkouts; `--audit-only` only checks current source identities.

See [VALIDATION.md](VALIDATION.md), [DEFENSIVE_SCOPE.md](DEFENSIVE_SCOPE.md) and `CURRENT_REVIEW.json` for measured scope and remaining work. Naming maps describe the earlier reorganization; readable new signature routines deliberately do not add another name-obfuscation layer. Names and repository quantity do not establish defensive value or CVP eligibility.
