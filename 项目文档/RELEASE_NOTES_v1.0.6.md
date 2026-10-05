# PEQuarry v1.0.6 local release candidate

Source: the public PEQuarry v1.0.5 commit `64e458d08db35fbafce2cdc2e48794a0f306b7dd`. This maintenance candidate changes only the current public tree and the three independently reproduced parser boundary defects below. Unpublished work is outside this candidate's source and scope.

- `get_word_at_rva` and `get_qword_at_rva` now request only the 2 or 8 bytes they decode. A valid 8 MiB mapped section previously caused a full-section `get_data` copy for one scalar; finite-result equivalence and a memory regression are checked.
- Scalar reads from raw data and file offsets now return `None` for negative integer offsets, including ordinary `int` subclasses. Python's negative slicing previously read an unrelated tail or produced a low-level unpack error.
- `parse_data_directories([indexes])` now removes all copies of a requested numeric index when the corresponding directory has a nonzero address, leaving absent entries in the list. Previously it checked for a string name but removed an integer, leaving a present request in the list or raising `ValueError` for a string list. This is list accounting, not a claim that all directory contents parse safely or completely.

The existing pefile MIT attribution and license remain. A complete deep audit/rewrite of all runtime algorithms has not been completed. Runtime parsing of arbitrary malformed inputs, Windows loader equivalence, remote CI, GitHub release assets, and CVP eligibility or approval remain OPEN. These notes describe a local candidate until the exact release commit, CI, tag, and downloadable assets are verified separately.
