# Contributing

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pre-commit install
```

## Workflow

1. Branch from `dev` (never commit detections straight to `main`).
2. Add or edit a Sigma rule under `rules/sigma/` with a unique UUID v4 `id` and at least one
   `attack.t...` MITRE tag.
3. Run the pipeline locally — this must pass before you open a PR:

   ```bash
   make all   # clean → compile → validate IDs → test
   ```

4. **Commit `id_registry.json`** whenever you add a rule (the compiler rewrites it; omitting
   it leaves IDs unstable across CI runs).
5. Open a PR against `dev`. CI runs the full pipeline and `pr_dry_run.yml` posts a deployment
   dry-run diff as a comment.

## Conventions

- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `ci:`).
- **Rule IDs:** Wazuh custom IDs are auto-assigned and must be ≥ 200000; never hand-edit them.
- **Field mappings:** new Sigma→Wazuh field names go in `FIELD_MAPPINGS` in
  `scripts/compile_sigma.py`.
- **Types:** code is type-hinted and checked with `mypy` via pre-commit; keep it clean.
- **Tests:** add coverage for new compiler behavior in `tests/test_compile_sigma.py`.
- **Secrets:** never commit credentials. See [`SECURITY.md`](SECURITY.md).
