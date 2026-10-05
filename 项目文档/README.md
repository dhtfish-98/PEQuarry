> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# PEQuarry

Bounded local PE inspection and static signature review, derived from [pefile](https://github.com/erocarrera/pefile). MIT attribution and the frozen upstream commit remain in [ORIGIN.md](<ORIGIN.md>).

Version 1.0.6 is a local candidate from the public v1.0.5 commit. It bounds 2/8-byte scalar RVA reads, returns `None` for negative scalar offsets and correctly accounts for requested directory indexes. [Release notes](<RELEASE_NOTES_v1.0.6.md>) give the exact scope and remaining checks. Version 1.0.5 removes unreachable verification branches that named an unrelated private project. Historical Git objects and v1.0.4 assets remain as published. Version 1.0.4 fixes a conditional verifier cleanup risk: running full `verify.py` directly from a root containing `Build` on a case-insensitive filesystem could resolve generated `build` to the staging tree. An exact directory-entry check preserves `Build`. The normal `Build/源码` and CI verification path has not shown this deletion. Three checks cover the preserved tree, generated output removal and symlink refusal. Version 1.0.3 adds independently written resource-tree, unsigned resource-string and parent-contained version-block parsing, plus bounded UTF-16 version editing. The 1.0.2 relocation/dynamic/function-override/exception and 1.0.1 input/mapping/signature rewrites remain. Other attributed directory parsers, opcode/structure helpers, aliases and ordinal tables remain. This is an ongoing defensive maintenance project; it is not a claim that every upstream algorithm has been rewritten.

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
- PE parsing: default cumulative budgets of 131,072 structure decodes, 1,048,576 `get_data` calls and 1,048,576 records/operand slots in the rewritten directory traversal (`max_directory_records`). Existing resource/import/export limits remain. These counters do not prove every directory algorithm, direct data slice or formatting path is fully bounded.
- Directory records: relocation blocks must advance by at least their header, remain inside the declared directory and contain aligned entries. Complete entries before a short standalone relocation tail remain available with a warning. Dynamic tables stay inside the selected raw section, and each dynamic/function/BDD payload stays inside its declared parent. Missing dynamic headers return a warning instead of dereferencing `None`. Unwind operands cannot consume code-slot padding or optional fields; incomplete unwind objects are not published. Reused unwind objects are decoded and registered once. A malformed traversal returns useful preceding records with warnings; a budget failure raises `quarry_LimitError`. Warnings and partial records do not imply a complete or valid directory. Oversized base-directory declarations remain partially inspectable; each actual RVA read is separately checked and never wraps.
- Resources and versions: an explicit stack checks actual metadata records, active-path cycles, parent extents and overlapping names. Size zero retains unknown-span compatibility with actual-read and work budgets. Unsigned UTF-16 string lengths and version String/Var lengths cannot read beyond parent blocks. `metadata_complete` and `strings_complete` expose incomplete traversal/string evidence; they are parsing-scope markers, not validity or security verdicts. Multiple string tables/translation records are parsed; the historical last-pair `.entry` and last-duplicate string result remain. Optional fixed values and Children may be absent. Character units share `max_directory_records`.
- Mapping: `max_virtual_address` retains the upstream starting-RVA selection convention; `max_mapped_size` additionally bounds the entire result before padding allocation. Relocation still changes parsed structure fields by the upstream API contract; raw bytes are restored even on a failed relocation/mapping. Mapping does not reproduce a verified Windows loader.
- Editing: byte setters reject spans beyond the existing file and permit the valid offset zero. `write()` returns a bytearray and retains normal header edits and small padding extensions. Invalid offsets and output growth beyond the input limit fail. UTF-16 version edits use actual UTF-16 content capacity and cannot resize the file or touch adjacent records; historical UTF-8 `entries_lengths` stays compatible. An explicit output path can overwrite an existing regular file; it rejects final links/devices and creates new files exclusively with mode 0600. A path created concurrently after the missing-path check is not overwritten. Writes are not atomic.
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

The verifier checks the current source manifest and runs 329 project checks, including the three 1.0.4 build-cleanup checks and ten 1.0.6 boundary cases. The fixed independent suite recorded 366 source-control passes and 364 maintained passes plus 2 strict reviewed legacy snapshot differences. This candidate's clean fixed checkout produced 372 PE observations: 370 exactly equal and 2 precisely corrected; the historical 1.0.3 record reported 373, so the one-observation count difference remains OPEN. `REVIEWED_VERSION_CHANGES.json` preserves old/current full results, Microsoft layout references and independent raw-byte decoding. Typed JSON keys fix an observer TypeError that previously hid `version_std` dump differences. Another 149 normal directory, 128 normal resource/version and 1,204 ordinary signature observations were exactly equal. The verifier builds/consumes the wheel in a fresh environment. It separately retains the historical unavailable/mismatched fixture failures. No input PE is executed. `--baseline PATH` and `--pe-tests PATH` reuse the fixed source/test checkouts; `--audit-only` only checks current source identities. Current candidate measurements are recorded in [VALIDATION.md](<VALIDATION.md>).

See [VALIDATION.md](<VALIDATION.md>), [DEFENSIVE_SCOPE.md](<DEFENSIVE_SCOPE.md>) and `CURRENT_REVIEW.json` for measured scope and remaining work. Naming maps describe the earlier reorganization; readable new signature, directory, resource and version routines deliberately do not add another name-obfuscation layer. Names and repository quantity do not establish defensive value or CVP eligibility.
