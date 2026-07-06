# Examples — Sigma in, Wazuh XML out

The compiled Wazuh rules live in `build/wazuh/` and are **gitignored** (a regenerable
artifact, not source). This folder is the opposite: a small, hand-picked set of
Sigma → Wazuh XML pairs committed to the repo so you can see exactly what
`scripts/compile_sigma.py` produces **without cloning, installing, or deploying
anything**.

Every `generated/*.xml` file here is copied straight out of a real build, not edited
by hand — the only change is a trailing newline added by this repo's standard
pre-commit `end-of-file-fixer` hook, the same normalization every committed file gets.
The compiler itself doesn't emit one, so a fresh `build/wazuh/*.xml` will diff by
exactly that one trailing byte; everything else matches exactly.

## How rules get hung off the Wazuh tree

There is no per-rule parent-SID selection. The compiler never tries to guess a
specific `<if_sid>` to chain onto. Instead it hangs every generated rule off a small,
fixed set of **decoder-defined parent groups** via `<if_group>`, chosen purely from the
Sigma `logsource` (`scripts/compile_sigma.py`, `get_parent_group()`):

| Sigma logsource                                   | Wazuh parent (`<if_group>`) |
|---------------------------------------------------|-----------------------------|
| `service: sysmon` or `category: process_creation` | `sysmon_event1`             |
| `service: syscheck`                               | `syscheck`                  |
| anything else                                     | `syslog`                    |

The bet: the parent group's job is only to gate on **event class** (this is a Sysmon
EventID 1 process-creation event, this is an FIM event). All of the actual detection
logic then rides in the child rule as `<field>` matches. That keeps parent selection
deterministic and dependency-free instead of trying to algorithmically walk the
built-in ruleset to find a plausible SID to hang off of.

## How Sigma boolean logic becomes Wazuh's flat `<field>` AND

Wazuh ANDs every `<field>` in a rule and has no native OR between fields, so the
compiler lowers each Sigma condition to **disjunctive normal form** and splits from
there (`evaluate_ast()`):

- **OR → separate rules.** Each OR-alternative becomes its own `<rule>` with its own
  auto-assigned ID. One Sigma rule can fan out into a family of Wazuh rules.
- **AND → multiple `<field>` elements.** Distinct fields become distinct `<field>`
  lines. Multiple `contains` on the *same* field collapse into one PCRE2
  lookahead conjunction: `(?=.*A)(?=.*B)`.
- **NOT → `negate="yes"`.** `not 1 of filter_*` is pushed down with De Morgan; the
  excluded alternatives merge under a single negated `<field>` via PCRE2 alternation.
- **Case-insensitivity** is forced with an inline `(?i)` because Wazuh's `pcre2` field
  type is case-sensitive by default (so `CertUtil.exe` can't slip past `certutil.exe`).

The compiler also **fails the build loudly** on anything it can't translate soundly —
`|base64`/`|base64offset`, `|re`, `|cidr`, numeric comparisons, null/empty values, and
field-less keyword matches — rather than emit a rule that silently never fires or
matches everything.

## The examples

### `01_certutil_download/` — AND-of-ORs fan-out
`condition: all of selection_*` where `selection_img` has 2 alternatives and
`selection_flags` has 3. The cartesian product `2 × 3 × 1` produces **6 Wazuh rules**
(`200017`–`200022`), each a single concrete AND-path. Note the same-field lookahead on
the command line: `(?=.*urlcache .*)(?=.*http.*)`.

### `02_netsh_fw_add_rule/` — exclusion via `negate="yes"`
`... and not 1 of filter_optional_*`. The two `selection_img` alternatives give
**2 rules** (`200150`–`200151`), each carrying a positive command-line match plus a
single negated `<field>` that alternates the two Dropbox false-positive command lines
under one `negate="yes"`.

### `03_whoami_as_param/` — the minimal case
A single `CommandLine|contains`. One field, one rule (`200197`). Useful as the
baseline for reading everything else.

### `04_lnx_clear_cmd_history/` — non-Sysmon parent
`logsource: { product: linux, service: syscheck }`, so it hangs off `<if_group>syscheck</if_group>`
instead of `sysmon_event1`, and the Sigma `file` field maps to `syscheck.path`. Shows
the parent-selection table doing its job outside of Windows process creation.

## Regenerate these yourself

```bash
python scripts/compile_sigma.py      # writes build/wazuh/*.xml
# then diff any file here against its freshly built counterpart, e.g.:
diff examples/01_certutil_download/generated/proc_creation_win_certutil_download_200017.xml \
     build/wazuh/proc_creation_win_certutil_download_200017.xml
# expect a one-line "\ No newline at end of file" diff (see above) and nothing else
```
