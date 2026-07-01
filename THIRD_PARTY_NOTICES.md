# Third-Party Notices

## SigmaHQ rules (`rules/sigma/sigmahq/`)

Rule files under `rules/sigma/sigmahq/` are imported from the
[SigmaHQ](https://github.com/SigmaHQ/sigma) community ruleset via
`scripts/sigmahq_coverage.py import`. They are **not** covered by this
repository's MIT `LICENSE` — they remain licensed by their original authors
under the **Detection Rule License (DRL) 1.1**:
<https://github.com/SigmaHQ/Detection-Rule-License>

Every imported file carries a provenance header recording:
- the original path in the upstream SigmaHQ repository,
- the pinned SigmaHQ ref/commit the import was taken from,
- the import date.

Nothing from the upstream SigmaHQ repository is vendored wholesale. The
fetch step (`scripts/sigmahq_coverage.py fetch`) sparse-clones only the
scoped subtree (`rules/windows/process_creation`) into the gitignored
`build/sigmahq_cache/` directory — that content is never committed to this
repo's history. Only the individual rules that verifiably compile cleanly
through `scripts/compile_sigma.py`, and that a human has explicitly selected
via `--limit`/`--allow`, are ever copied into `rules/sigma/sigmahq/`.

See [`docs/COVERAGE.md`](docs/COVERAGE.md) for the current coverage report
and `scripts/sigmahq_coverage.py` for the fetch/report/import tooling.
