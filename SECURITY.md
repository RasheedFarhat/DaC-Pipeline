# Security Policy

## Reporting a vulnerability

This is a personal portfolio / lab project, not production software. If you find a security
issue, please open a GitHub issue marked **[security]**, or contact the maintainer directly.
There is no formal SLA, but reports are appreciated and will be acknowledged.

## Secret handling

- **No credentials are committed.** Runtime secrets live in `.env` and `.secrets`, both of
  which are gitignored.
- Deployment reads `WAZUH_USER` / `WAZUH_PASSWORD` from the environment (locally via `.env`,
  in CI via GitHub Actions repository secrets). See the deployment section of the README.
- TLS verification is enabled by default (`WAZUH_VERIFY_TLS=true`). Prefer `WAZUH_CA_BUNDLE`
  over disabling verification for self-signed managers.

## Credential exposure — remediated by rotation (2026-06-29)

An earlier commit (`b0ba093`, later removed in `a76308c`) hardcoded a lab Wazuh password,
`MyS3cr37P450r…`, before it was moved to environment variables. The plaintext value still
exists in two historical commits.

**Status: remediated by rotation.** The leaked credential was rotated on the Wazuh manager;
the historical value is **dead** and confirmed no longer active as of **2026-06-29**. The
string is therefore an inert artifact.

**Why the history was not rewritten.** A `git filter-repo` scrub + force-push was evaluated
and deliberately declined:

- The value is already dead, so a rewrite removes a string, not a live risk.
- **Every branch in the repo descends from the leaked commit** (all local and remote
  branches), so a scrub would force-rewrite and force-push the entire branch set —
  invalidating every existing clone and all open work.
- GitHub **caches commits by SHA** even after a force-push; the old commit would remain
  reachable by URL until GitHub Support runs garbage collection on request. A faithful
  scrub would still require a Support ticket (or deleting and recreating the repo, which
  would discard the PR/issue history this portfolio repo intentionally keeps).

For a low-risk, already-rotated lab credential, rotation is the proportionate remediation;
the PR/issue history is retained as a portfolio asset.

> **Note:** `WazuhDeploy2026!` was **never committed** — `.gitignore` caught the `.env` /
> `.secrets` files holding it before it could enter history. It is not a history-scrub
> target; only ensure it (the current password) is rotated on the manager and present in
> the local `.env` and the GitHub Actions deploy secret.

**Prevent recurrence:** secret scanning runs in CI on full history (`gitleaks`), `.env` and
`.secrets` are gitignored, and `CodeQL` / `bandit` / `pip-audit` gate every change. Never
re-introduce literal credentials in source.
