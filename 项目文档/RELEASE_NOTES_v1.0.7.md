# PEQuarry v1.0.7 local release candidate

Source: the current public PEQuarry v1.0.6 commit `011ad5a9badae78e6eb7e1ebc8f714ea61c79036`. This candidate adds three narrow parser corrections identified with complete, never-executed PE files and the frozen attributed upstream control. It does not include the separate unpublished 1.0.21 candidate.

- A short Type 20 debug payload no longer raises `AttributeError` during ordinary `PE(data=...)` or `PE(path)` parsing. The debug directory entry remains visible with `entry=None`; a complete four-byte payload still decodes its flags.
- PE32 delay-import VA normalization now obtains `phmod` from its own descriptor field. A full-file sample with distinct `phmod` and `pUnloadIAT` values decodes them as distinct RVAs.
- PE32+ `relocate_image()` now applies the base delta once to `GuardRFFailureRoutineFunctionPointer` and once to `GuardRFVerifyStackPointerFunctionPointer` when each is present. A complete load-config/base-relocation file verifies both fields and a separate DIR64 relocation; an absent verify pointer remains zero.

Four focused tests cover five full-file scenarios. Declared import/export/TLS directory-size behavior remains under review; these tests do not establish Windows loader equivalence or safety for arbitrary malformed inputs. The existing pefile MIT attribution and license remain. A full audit or rewrite of all runtime algorithms is OPEN. Local source and package checks have passed; remote CI, release assets, CVP eligibility and applicant identity require separate evidence tied to the final commit.
