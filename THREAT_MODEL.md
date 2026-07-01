# Threat Model

This document models the security posture of **this** pipeline — the path a Sigma
rule travels from a developer's editor to a live Wazuh manager — not threat
detection in general. It names the trust boundaries that change ownership of an
artifact, what is assumed safe on each side, what could go wrong, and the specific
control in this repo that addresses it. Where a control is partial or deferred,
that is stated.

The detections this pipeline *ships* (what they catch on monitored endpoints) are
out of scope here except for the ATT&CK coverage table at the end; this is about
the security of the delivery mechanism itself.

## Pipeline at a glance

```
 Developer        GitHub                GitHub Actions            Wazuh
 workstation  →   (Git remote,     →    (ubuntu-latest CI    →    manager
 (Sigma YAML)     PRs, secrets)         + self-hosted CD)         (REST API → rules)
```

Each arrow is a trust boundary: the artifact crosses from one party's control into
another's. The four hops are analyzed below.

---

## Trust boundaries

### Boundary 1 — Developer workstation → Git / GitHub

**Crosses:** Sigma YAML, compiler/deploy Python, workflow definitions,
`id_registry.json`, `field_mappings.yaml`.

**Trusted on the inbound side:** the author's identity (Git commit/GitHub auth)
and that branch protection forces changes through a reviewed pull request before
they reach `dev`/`main`.

**What could go wrong**

- *A committed secret.* The Wazuh API password, a `.env`, or a CA key gets
  committed. This has already happened once in this repo's history (the
  `MyS3cr37P450r…` lab credential). It is **remediated by rotation** — the leaked
  value is dead on the Wazuh manager — so the string remaining in history is inert.
  The history was deliberately *not* rewritten (see Controls below).
- *A malicious or careless rule/code change.* A Sigma rule or a compiler edit that,
  once compiled and deployed, weakens the live ruleset (e.g. a rule that never
  fires, or a compiler change that drops rules).
- *A poisoned `id_registry.json`.* Hand-editing the registry to collide IDs or
  point a UUID at a built-in ID range.

**Controls in this repo**

- **gitleaks runs on every push and PR over full history** (`fetch-depth: 0`), so
  a credential committed *anywhere* in history — not just in the new commits —
  fails the check. `.gitleaks.toml` extends the default ruleset and allowlists
  exactly the two historical commits holding the already-rotated lab credential;
  the allowlist is scoped to those commit SHAs, so it does not weaken detection on
  any other commit, past or future. A history rewrite was considered and
  **declined**: the leaked value is dead (rotated), every branch in the repo
  descends from the leaked commit so a scrub would force-rewrite the entire branch
  set, and GitHub would still cache the old commit by SHA. The string is retained
  in history as an inert artifact; see `SECURITY.md` for the full rationale.
- **`.env` and `.secrets` are gitignored**; secrets live in GitHub Actions secrets,
  not the tree.
- **`check_rule_ids.py` gates the registry**: Wazuh IDs must be integers ≥ 200000
  (below that is Wazuh built-in / reserved space), every XML must carry a
  `<!-- sigma_uuid:UUID -->` comment linking it back to a Sigma rule, and no ID or
  UUID may collide. A poisoned registry fails CI before it can be deployed.
- **Branch protection + PR review** mean no single actor lands a rule or compiler
  change unreviewed; `pr_dry_run.yml` surfaces the *deployment* effect of the change
  as a PR comment so a reviewer sees what would actually deploy.

### Boundary 2 — GitHub → GitHub Actions runner

**Crosses:** the checked-out repo and (on CD) the Wazuh secrets, into an execution
environment that runs third-party Actions and installs PyPI packages.

**Trusted on the inbound side:** the integrity of the Actions and dependencies the
workflow pulls in, and — for CD — the self-hosted runner host.

**What could go wrong**

- *A compromised third-party Action.* A tag like `actions/checkout@v4` is mutable;
  an attacker who moves the tag (or compromises the action) runs arbitrary code in
  a job that, on CD, holds the Wazuh credentials.
- *A malicious dependency / known CVE.* A compromised or vulnerable transitive
  package executes during `pip install` or at compile time.
- *Secret exfiltration on the self-hosted CD runner.* The `deploy` job runs on a
  `self-hosted` runner in the `production` environment with `WAZUH_USER` /
  `WAZUH_PASSWORD` in its env.

**Controls in this repo**

- **Every Action is pinned to an immutable commit SHA, not a tag** — e.g.
  `actions/checkout@9c091bb…`, `actions/setup-python@ece7cb06…`,
  `github/codeql-action/*@dd903d2e…`, `gitleaks/gitleaks-action@e0c47f4f…`.
  Moving a tag cannot change what runs; an upgrade is an explicit, reviewable diff.
- **Dependabot** proposes those SHA bumps (and pip updates) weekly, so pinning does
  not mean going stale — upgrades arrive as reviewed PRs.
- **CodeQL and bandit** run Python SAST on every push/PR. bandit gates on Medium+
  severity, with a small set of IDs skipped and each skip justified inline
  (`B105` is the `OFFLINE_DRY_RUN_TOKEN` sentinel, not a credential; `B404/B603`
  are `sigma-cli` invoked via a resolved absolute path with list args and no shell;
  `B405/B314` parse build output this pipeline just generated, not untrusted input).
- **pip-audit** fails the build on any known CVE in `requirements.txt`, with a
  single documented, time-boxed exception (`CVE-2025-69872` in `diskcache`, a
  transitive dependency of pySigma with no upstream fix yet — tracked for removal).
- **`requirements.txt` is a `pip-compile` lock** generated from `requirements.in`,
  so the full transitive set is pinned and auditable rather than resolved freshly
  per run.
- **Read-only token scope.** The scanning workflows declare `permissions:
  contents: read` (CodeQL additionally needs `security-events: write` to upload
  results) — a compromised step cannot push to the repo with the default token.
- **Least-privilege CD trigger.** `deploy.yml` is `workflow_dispatch` only (no
  push/PR auto-deploy) and bound to the `production` GitHub Environment, so the
  Wazuh secrets are only ever exposed on a deliberate, dispatched deploy. The
  self-hosted runner host itself remains a trusted component (see Residual risks).

### Boundary 3 — Runner → Wazuh REST API

**Crosses:** the bundled rule XML and `agent.conf` over the network to the manager's
API, authenticated with a username/password that mints a short-lived JWT.

**Trusted on the inbound side:** the API endpoint's TLS identity and the manager's
authorization of the deploy user.

**What could go wrong**

- *MITM / spoofed manager.* Deploying rules to, or sending credentials to, an
  impostor endpoint.
- *Token expiry mid-deploy.* The Wazuh JWT is short-lived (15 min by default); a
  long reconcile-and-deploy can outlive its token and fail partway through.
- *Transient API failure.* A 429 or 5xx leaving the ruleset half-applied.

**Controls in this repo**

- **TLS verification is on by default** (`wazuh_verify_tls=True`).
  `WAZUH_CA_BUNDLE` is offered as the *preferred* path for self-signed installs so
  verification stays on; disabling it is an explicit, logged "INSECURE MODE"
  opt-out, not a silent default.
- **401 re-auth path** (`authed_request`): on a 401 the client re-authenticates
  **exactly once** and retries, then threads the refreshed token to later calls so
  the rest of the deploy reuses it. A *second* 401 after re-auth is propagated, not
  retried — that distinguishes "token expired" (recoverable) from "credentials
  rejected" (a real failure that should stop the deploy), avoiding an auth-retry
  loop against the manager. The dry-run sentinel token short-circuits this entirely.
- **Bounded retry on transient faults** (`tenacity`): only 429 / 5xx / connection /
  timeout errors retry, with exponential backoff capped at 5 attempts. A 4xx other
  than the handled 401 fails fast rather than hammering the API.

### Boundary 4 — Wazuh API → live manager ruleset

**Crosses:** the API write actually mutates the running detection ruleset and
restarts the manager.

**Trusted on the inbound side:** that the set of files the deploy chooses to write
and delete reflects the repo's intent.

**What could go wrong**

- *Silent ruleset wipe.* A bundling bug drops rules, and the post-restart manager
  comes up with an incomplete or empty ruleset — detection coverage silently lost.
- *Mass deletion of foreign rules.* Reconciliation sees many remote rule files that
  aren't in the build and deletes production detections that were never owned by
  this repo.
- *Double-firing rules.* Pre-bundle per-rule files left on the manager fire
  alongside the new single bundle.

**Controls in this repo**

- **Bundle-completeness abort.** `deploy_rules` refuses to deploy unless *every*
  XML in `build/wazuh/` parsed into the bundle (`bundled_count != len(xml_files)`
  → `sys.exit(1)`). A bundle that silently dropped rules would, after restart, wipe
  live coverage — so it halts before writing anything.
- **Blast-radius guard on foreign deletes.** Reconciliation splits orphaned remote
  files into *superseded* (names that match the current build output — expected
  pre-bundle migration artifacts, safe to delete) and *foreign* (everything else:
  hand-added rules, or rules deleted from the repo). If **more than 5 foreign**
  files would be deleted, the deploy aborts (`DELETE_THRESHOLD = 5`). Rationale: a
  legitimate change rarely retires more than a handful of foreign rules at once, so
  a large foreign-delete set signals a logic error or a reconcile run against the
  wrong manager — exactly the case where silently purging production rules is
  catastrophic and unrecoverable without backup. Superseded files bypass the guard
  by design, because they *must* be deleted to stop double-firing and their count
  scales with the repo's own rule count, not with blast radius.
- **Dry-run preview.** `--dry-run` (and `pr_dry_run.yml` on every PR) reports what
  *would* be deleted/deployed, including a warning when the foreign count would trip
  the guard, so the blast radius is visible before any real deploy.
- **Response-body check on every `/rules/files/*` call, not just HTTP status.**
  Wazuh's API can return HTTP 200 while the write or delete itself was silently
  skipped — the only signal is the JSON body's `error` / `total_failed_items`
  fields. Confirmed against a live manager on two separate occasions: a PUT without
  `overwrite=true` against an existing filename, and a DELETE of a file that no
  longer exists, both returned 200 with `error: 1` and left the manager untouched.
  `assert_wazuh_result_ok` checks the body after every PUT/DELETE; a body-level
  failure raises and is treated the same as a network/HTTP error — reconciliation
  aborts the rest of the delete loop on the first such failure rather than silently
  continuing with a partially-deleted orphan set.
- **Per-rule group membership preserved through bundling.** The bundler used to
  wrap every rule in one generic `custom_sigma` group regardless of its Sigma
  `logsource.product`/`service`, silently discarding `group:windows` /
  `group:linux` filtering for all deployed rules (`check_rule_ids.py` couldn't
  catch this — it validates the individual `build/wazuh/*.xml` files, never the
  bundle that's actually deployed). The bundler now emits one `<group name="X">`
  block per distinct name, matching Wazuh's own multi-group rule-file convention;
  verified against a live manager via the rules API (`group:windows` / `group:linux`
  filters correctly return the expected custom rules, not just the file text).

---

## Supply-chain surface of the pipeline itself

The pipeline's own supply chain has three ingress points; each has a mapped control:

| Ingress | Risk | Control |
|---|---|---|
| **GitHub Actions** pulled into CI/CD | mutable tag repoint / action compromise runs code beside the Wazuh secrets | **SHA-pinned** to immutable commits; **Dependabot** keeps pins fresh as reviewed PRs |
| **PyPI dependencies** (`requirements.txt`) | vulnerable or malicious package executes at install/compile | **pip-audit** fails on known CVEs; **`pip-compile` lock** pins the full transitive tree; **Dependabot** bumps them |
| **First-party code** (`scripts/`, rules) | a credential leak or an injected/unsafe code path is committed | **gitleaks** (full history) on secrets; **CodeQL + bandit** SAST on code; **PR review + dry-run** on behavior |

The defense is layered on purpose: SHA-pinning closes the *tag-mutation* vector,
pip-audit closes the *known-CVE* vector, CodeQL/bandit close the *injected-code*
vector, and gitleaks closes the *leaked-secret* vector. No single one covers
another's gap.

---

## Detection coverage (ATT&CK)

The detections this pipeline currently ships and the MITRE ATT&CK techniques each
maps to (tags are declared in the Sigma source and carried through to the compiled
Wazuh rules). Current state: **58 Sigma rules** (3 hand-authored + 55 curated
imports from SigmaHQ) compiling to **216 Wazuh rules**, spanning **119 distinct
ATT&CK techniques across all 14 tactics**. Full per-rule detail lives in
[`docs/COVERAGE.md`](docs/COVERAGE.md) (generated by `scripts/sigmahq_coverage.py`)
and the provenance headers in `rules/sigma/sigmahq/*.yml`; the three hand-authored
rules are called out individually below because their fan-out illustrates the
compiler's DNF distribution concretely:

| Sigma rule | Wazuh ID(s) | ATT&CK technique | Tactic |
|---|---|---|---|
| `lnx_clear_cmd_history.yml` | 200000 | **T1070.003** — Indicator Removal: Clear Command History | Defense Evasion |
| `sysmon_certutil_download.yml` | 200001 | **T1105** — Ingress Tool Transfer (`certutil` LOLBin download) | Command and Control |
| `sysmon_wmic_xsl_bypass.yml` | 200005–200016 | **T1220** — XSL Script Processing (WMIC `/format:` AppLocker bypass) | Defense Evasion |

`sysmon_wmic_xsl_bypass.yml` fans out to 12 Wazuh rules (200005–200016): the
compiler distributes its nested OR condition into disjunctive normal form, emitting
one rule per alternative. All three hand-authored rules are `level: high`.

The 55 SigmaHQ imports were selected in two passes: 5 well-known, easily
explainable techniques (Mimikatz execution, PsExec lateral movement, Certutil
LOLBin download, Comsvcs.dll LSASS dumping, Mshta HTTP execution), then 50 more
chosen by greedy maximum-coverage selection to spread across as many distinct
ATT&CK tactics/techniques as possible rather than clustering on one category —
every candidate was also checked against `MAX_AND_CLAUSE_PRODUCT` (excluded if it
would expand past 10 Wazuh rule IDs) so no single import dominates the ruleset.

---

## Residual risks (accepted / deferred)

These are known and **not** currently mitigated in-repo; they are listed so the gap
is explicit rather than implied-safe:

- **`--dry-run` remote diff is unverified against a live manager.** If the API
  response shape differs from the two cases handled, the diff silently treats all
  remote rules as new. Tracked future work (also noted in the README).
- **Self-hosted CD runner is a trusted host.** A compromise of that machine
  exposes the Wazuh credentials in the `deploy` job's environment. Hardening the
  runner host is outside this repo.
- **Inert leaked string retained in history.** The `MyS3cr37P450r…` lab credential
  remains visible in two historical commits. It is remediated by rotation (the value
  is dead), and a history rewrite was deliberately declined (whole-repo blast radius
  + GitHub SHA caching for a low-risk dead value). The gitleaks allowlist keeps those
  two commits whitelisted to keep the scan green; it is scoped to those SHAs only.
  (`WazuhDeploy2026!` was *never* committed — `.gitignore` caught it — so it is not
  a history item at all.)
- **`diskcache` `CVE-2025-69872`** is accepted via pip-audit ignore until pySigma
  ships a patched transitive dependency.
