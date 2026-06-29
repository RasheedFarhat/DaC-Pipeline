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

## Credential rotation — history remediation (action required)

An earlier commit on this repository hardcoded a lab Wazuh password before it was moved to
environment variables. The plaintext value still exists in Git history. Because this is a
lab credential it carries low risk, but it must be rotated and scrubbed:

1. **Rotate the lab credential** on the Wazuh manager so the historical value is dead.
2. **Scrub history** with [git-filter-repo](https://github.com/newren/git-filter-repo):

   ```bash
   pip install git-filter-repo
   # one line per leaked literal
   printf 'OLD_PASSWORD_1==>***REMOVED***\nOLD_PASSWORD_2==>***REMOVED***\n' > /tmp/redactions.txt
   git filter-repo --replace-text /tmp/redactions.txt
   # filter-repo drops the remote by design; re-add and force-push:
   git remote add origin git@github.com:RasheedFarhat/DaC-Pipeline.git
   git push --force --all && git push --force --tags
   ```

   > ⚠️ This rewrites every commit hash. Coordinate with any collaborators and re-clone
   > afterward. Back up the repo first.

3. **Prevent recurrence:** secret scanning runs in CI (see `gitleaks` in the CI workflow)
   and `.env` / `.secrets` are gitignored. Never re-introduce literal credentials in source.
