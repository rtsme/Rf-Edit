# AGENTS.md — Rf-Edit

**The rules for working here are in the RF Online Combiner umbrella's
`AGENTS.md`** (repo `rtsme/rf-combiner`; on James's machine this clone sits
in the umbrella's `repos\` folder, so it is `..\..\AGENTS.md`). Read it
before changing anything here, and follow it. Its "Making a change" section
says which rule and spec shard apply (for the data tooling: spec 02 and
rule 5). This file is only a pointer; any agent (Claude Code, Codex,
another) is bound by the umbrella's rules.

If the umbrella is not beside this checkout, these still hold here:
- **A schema's column order is the binary record layout.** A change to
  `rf_dat.py`, `rf_edf.py`, `rf_repo.py` or a schema must still round-trip
  every table byte-for-byte: run `python verify_all.py "<dir of .dat
  files>"` on a raw `.dat` directory (not an rf-data repo) and the
  `test_rf_*.py` suites (`python -m unittest test_rf_repo -v`, and the
  same for `test_rf_dat` and `test_rf_edf`), and name what you ran.
- `rf_repo.py` filters credential-looking keys out of rf-data; never weaken
  that filter to make a build pass.
- Changes merge only by PR from a `task/<slug>` branch; never push to
  `main`.
