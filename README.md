# PEQuarry

Portable Executable structure, malformed-input, import/export, resource, checksum and byte-preserving write analysis. This is an attributed, reorganized derivative of pefile, with scope-resolved binding/file/module renaming and explicit API/schema adapters. It supports lawful offline security research and static analysis. Upstream algorithms and history remain credited.

## Install and use

Runtime package metadata supports Python >=3.9. The pinned verification dependencies require Python >=3.10; use Python 3.12 for the commands below. Recorded checks use Python 3.12.13; Python 3.9 execution has not been measured.

```python
from pequarry import image_reader
image = image_reader.quarry_PE("sample.exe")
print(image.FILE_HEADER.Machine, len(image.sections))
print(image.quarry_get_imphash())
image.quarry_close()
```

## Verification

```sh
python -m pip install '.[test]'
python verify.py
```

The verifier downloads pinned upstream source (and the pinned PE test repository for PEQuarry), compares the same offline inputs, builds a wheel/source distribution, verifies every Python file inside the wheel and consumes that wheel in a separate temporary environment. Supply `--baseline PATH` and `--pe-tests PATH` to reuse existing local checkouts. No binary fixture is executed. `--audit-only` checks the frozen source/asset bytes and executable modes. The workflow checks out its triggering commit before running the same command.

## Structure

image_reader owns parsing, physical layouts and PE operations; signature_tools owns static signature/packing statistics; ordinal_catalog isolates DLL ordinal-name data. api_contract maps external Windows schema labels and public aliases to the renamed implementation and routes mutable module settings consistently.

See [ORIGIN.md](ORIGIN.md), [VALIDATION.md](VALIDATION.md), `SYMBOL_MAP.json`, `FILE_MAP.json`, `NAME_AUDIT.json` and `SOURCE_MANIFEST.json` for source/licensing, measured evidence, exact naming exceptions and file hashes.
