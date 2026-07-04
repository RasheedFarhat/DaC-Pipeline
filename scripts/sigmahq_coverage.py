"""SigmaHQ coverage tool.

Pulls a pinned, scoped slice of the upstream SigmaHQ ruleset (Windows
process_creation / Sysmon), runs each rule through the *same* fail-loud
compile checks `compile_sigma.py` uses for real, and reports how much of that
slice compiles cleanly today — bucketed by whichever unsupported construct
blocked the rest. Optionally copies a curated selection of the clean rules
into rules/sigma/ with source provenance.

SigmaHQ's rules are licensed under the Detection Rule License (DRL) 1.1, not
this repo's MIT license (see THIRD_PARTY_NOTICES.md). Nothing upstream is
vendored: `fetch` sparse-clones only the scoped path into the gitignored
build/ directory, and `import` only ever copies the individual rules a human
explicitly selected via --limit/--allow.
"""

import argparse
import glob
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compile_sigma as cs  # noqa: E402  (reuse the real fail-loud compile logic)

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

SIGMAHQ_LICENSE_NAME = "Detection Rule License (DRL) 1.1"
SIGMAHQ_LICENSE_URL = "https://github.com/SigmaHQ/Detection-Rule-License"

DEFAULT_SIGMAHQ_CONFIG: Dict[str, Any] = {
    "repo_url": "https://github.com/SigmaHQ/sigma.git",
    "pinned_ref": "r2026-04-01",
    "scope_paths": ["rules/windows/process_creation"],
    "cache_dir": "build/sigmahq_cache",
    "import_dir": "rules/sigma/sigmahq",
}


def load_sigmahq_config() -> Dict[str, Any]:
    try:
        with open("pipeline.yaml", "r") as f:
            config = yaml.safe_load(f) or {}
    except FileNotFoundError:
        config = {}
    sigmahq = config.get("sigmahq", {}) or {}
    merged = dict(DEFAULT_SIGMAHQ_CONFIG)
    merged.update(sigmahq)
    return merged


@dataclass
class RuleResult:
    """One bucketed outcome for one Sigma rule (or unparseable file)."""

    source_path: str
    title: str
    bucket: str
    detail: str
    uuid: Optional[str] = None
    unmapped_fields: List[str] = field(default_factory=list)
    yaml_text: str = ""

    def to_json(self) -> Dict[str, Any]:
        return {
            "source_path": self.source_path,
            "title": self.title,
            "bucket": self.bucket,
            "detail": self.detail,
            "uuid": self.uuid,
            "unmapped_fields": self.unmapped_fields,
        }


# --- Fetch: pinned sparse clone -------------------------------------------------

def _run(cmd: List[str], cwd: Optional[str] = None) -> None:
    logger.debug("Running: %s", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True)


def _fetched_marker(cache_dir: str) -> str:
    return os.path.join(cache_dir, ".fetched_ref")


def fetch(ref: str, cache_dir: str, repo_url: str, scope_paths: List[str], force: bool = False) -> None:
    marker = _fetched_marker(cache_dir)
    if not force and os.path.isfile(marker):
        with open(marker, "r") as f:
            if f.read().strip() == ref:
                logger.info(f"{cache_dir} already at ref '{ref}' (use --force to refetch).")
                return

    if os.path.isdir(cache_dir):
        shutil.rmtree(cache_dir)
    parent = os.path.dirname(cache_dir) or "."
    os.makedirs(parent, exist_ok=True)

    logger.info(f"Sparse-cloning {repo_url} at '{ref}' (scope: {', '.join(scope_paths)})...")
    _run(["git", "clone", "--filter=blob:none", "--no-checkout", repo_url, cache_dir])
    _run(["git", "sparse-checkout", "init", "--cone"], cwd=cache_dir)
    _run(["git", "sparse-checkout", "set", *scope_paths], cwd=cache_dir)
    _run(["git", "checkout", ref], cwd=cache_dir)

    license_text = subprocess.run(
        ["git", "show", f"{ref}:LICENSE"], cwd=cache_dir,
        capture_output=True, text=True, check=True,
    ).stdout
    with open(os.path.join(cache_dir, "UPSTREAM_LICENSE"), "w") as f:
        f.write(license_text)

    with open(marker, "w") as f:
        f.write(ref)
    logger.info(f"Fetched '{ref}' into {cache_dir}.")


def current_sha(cache_dir: str) -> str:
    out = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=cache_dir,
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


# --- Classification: reuse compile_sigma.py's fail-loud checks -----------------

def _bucket_from_error(exc: Exception) -> str:
    """Map a raised exception to a stable bucket name for the frequency table.

    Matches the exact wording `compile_sigma.py` raises today (assert_supported_
    constructs / evaluate_ast) so upstream message changes fail this tool loudly
    (a KeyError-free fallback bucket) rather than silently mis-bucketing.
    """
    msg = str(exc)
    if isinstance(exc, NotImplementedError):
        m = re.search(r"Unsupported Sigma modifier '\|(\w+)'", msg)
        if m:
            return f"unsupported_modifier:{m.group(1)}"
        m = re.search(r"Unsupported Sigma value type '(\w+)'", msg)
        if m:
            return f"unsupported_value_type:{m.group(1)}"
        if "field-less" in msg:
            return "unsupported_leaf:keyword"
        return "unsupported_construct:other"
    if isinstance(exc, ValueError):
        if "null value" in msg:
            return "null_value"
        if "empty value" in msg:
            return "empty_value"
        return "value_error:other"
    return f"error:{type(exc).__name__}"


def _used_fields(rule: Any) -> List[str]:
    """Every Sigma field name referenced anywhere in the rule's detections.

    Scoped the same way `assert_supported_constructs` already is (all named
    detections, not just those reachable from the first `condition:`) — a
    superset, which only makes the unmapped-field bucket a directional signal
    rather than a precise reachability analysis.
    """
    used = set()
    if not rule.detection or not rule.detection.detections:
        return []
    for detection in rule.detection.detections.values():
        for item in cs._iter_detection_items(detection):
            f = getattr(item, "field", None)
            if f:
                used.add(f)
    return sorted(used)


def classify_rule_text(yaml_text: str, source_path: str) -> List[RuleResult]:
    """Run one Sigma YAML file's rule(s) through the real compile checks and bucket them."""
    try:
        collection = SigmaCollection.from_yaml(yaml_text)
    except SigmaError as e:
        return [RuleResult(source_path, source_path, "pysigma_parse_error", str(e))]
    except Exception as e:  # malformed YAML etc. — still a build-time rejection
        return [RuleResult(source_path, source_path, "pysigma_parse_error", f"{type(e).__name__}: {e}")]

    results: List[RuleResult] = []
    for rule in collection.rules:
        # Correlation rules have no detection AST; compile_sigma.py rejects them
        # the same way, so bucket them as an unsupported rule type.
        if not isinstance(rule, SigmaRule):
            results.append(RuleResult(
                source_path, source_path,
                f"unsupported_rule_type:{type(rule).__name__}",
                "only standard Sigma detection rules can be compiled",
                str(rule.id) if rule.id else None,
            ))
            continue

        uuid = str(rule.id) if rule.id else None
        title = rule.title or source_path

        try:
            cs.assert_supported_constructs(rule)
            conditions = rule.detection.parsed_condition if rule.detection else []
            if not conditions:
                raise NotImplementedError("Rule has no parsed condition")
            # Mirrors compile_sigma.main(): only the first condition is compiled.
            cs.evaluate_ast(conditions[0].parsed, rule)
        except Exception as e:
            results.append(RuleResult(source_path, title, _bucket_from_error(e), str(e), uuid))
            continue

        unmapped = [f for f in _used_fields(rule) if f not in cs.FIELD_MAPPINGS]
        if unmapped:
            results.append(RuleResult(
                source_path, title, "unmapped_field", ", ".join(unmapped), uuid,
                unmapped_fields=unmapped, yaml_text=yaml_text,
            ))
        else:
            results.append(RuleResult(source_path, title, "clean", "", uuid, yaml_text=yaml_text))

    return results


def _collect_rule_files(cache_dir: str, scope_paths: List[str]) -> List[str]:
    files: List[str] = []
    for scope in scope_paths:
        pattern = os.path.join(cache_dir, scope, "**", "*.yml")
        files.extend(glob.glob(pattern, recursive=True))
    return sorted(files)


def classify_all(cache_dir: str, scope_paths: List[str]) -> List[RuleResult]:
    results: List[RuleResult] = []
    for path in _collect_rule_files(cache_dir, scope_paths):
        rel = os.path.relpath(path, cache_dir)
        with open(path, "r") as f:
            text = f.read()
        results.extend(classify_rule_text(text, rel))
    return results


# --- Report ----------------------------------------------------------------------

def render_report(results: List[RuleResult], ref: str, sha: str, repo_url: str, generated_on: str) -> str:
    total = len(results)
    clean = [r for r in results if r.bucket == "clean"]
    unmapped = [r for r in results if r.bucket == "unmapped_field"]
    failed = [r for r in results if r.bucket not in ("clean", "unmapped_field")]

    pct = (100.0 * len(clean) / total) if total else 0.0
    bucket_counts = Counter(r.bucket for r in failed)
    field_counts: Counter = Counter()
    for r in unmapped:
        field_counts.update(r.unmapped_fields)

    lines: List[str] = []
    lines.append("# SigmaHQ Coverage Report")
    lines.append("")
    lines.append(
        f"Generated {generated_on} against [SigmaHQ](https://github.com/SigmaHQ/sigma) "
        f"`{ref}` (`{sha}`), scope: Windows `process_creation` / Sysmon rules."
    )
    lines.append("")
    lines.append(f"## Coverage: {pct:.1f}% ({len(clean)} / {total} rules compiled clean)")
    lines.append("")
    lines.append(f"- Clean: {len(clean)}")
    lines.append(f"- Compiles, unmapped field(s): {len(unmapped)}")
    lines.append(f"- Failed: {len(failed)}")
    lines.append("")

    lines.append("## Failure buckets, ranked by frequency")
    lines.append("")
    lines.append("The top row is the next compiler feature worth building.")
    lines.append("")
    lines.append("| Bucket | Count |")
    lines.append("|---|---|")
    for bucket, count in bucket_counts.most_common():
        lines.append(f"| `{bucket}` | {count} |")
    if not bucket_counts:
        lines.append("| _(none)_ | |")
    lines.append("")

    lines.append("## Top unmapped fields by count")
    lines.append("")
    lines.append(
        "Cheapest coverage win in this report: each row is a one-line addition "
        "to `field_mappings.yaml`."
    )
    lines.append("")
    lines.append("| Field | Rules affected |")
    lines.append("|---|---|")
    for f, count in field_counts.most_common():
        lines.append(f"| `{f}` | {count} |")
    if not field_counts:
        lines.append("| _(none)_ | |")
    lines.append("")

    lines.append("## Rule listing")
    lines.append("")
    lines.append(f"### Clean ({len(clean)})")
    for r in sorted(clean, key=lambda r: r.source_path):
        lines.append(f"- `{r.source_path}` — {r.title}")
    lines.append("")

    lines.append(f"### Compiles, unmapped field(s) ({len(unmapped)})")
    for r in sorted(unmapped, key=lambda r: r.source_path):
        lines.append(f"- `{r.source_path}` — {r.title} (unmapped: {r.detail})")
    lines.append("")

    for bucket, _count in bucket_counts.most_common():
        bucket_results = sorted((r for r in failed if r.bucket == bucket), key=lambda r: r.source_path)
        lines.append(f"### Failed: `{bucket}` ({len(bucket_results)})")
        for r in bucket_results:
            lines.append(f"- `{r.source_path}` — {r.title}: {r.detail}")
        lines.append("")

    return "\n".join(lines)


# --- Import ------------------------------------------------------------------

def _provenance_header(source_path: str, ref: str, sha: str, repo_url: str) -> str:
    today = date.today().isoformat()
    return (
        f"# Imported from SigmaHQ ({repo_url})\n"
        f"# Source path: {source_path}\n"
        f"# Pinned ref: {ref} ({sha})\n"
        f"# License: {SIGMAHQ_LICENSE_NAME} — see THIRD_PARTY_NOTICES.md ({SIGMAHQ_LICENSE_URL})\n"
        f"# Imported: {today}, verified compiled clean by scripts/sigmahq_coverage.py\n"
    )


def _existing_import_uuids(import_dir: str) -> set:
    uuids: set = set()
    if not os.path.isdir(import_dir):
        return uuids
    for name in os.listdir(import_dir):
        if not name.endswith((".yml", ".yaml")):
            continue
        with open(os.path.join(import_dir, name), "r") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict) and data.get("id"):
            uuids.add(str(data["id"]))
    return uuids


def _load_allowlist(path: str) -> set:
    with open(path, "r") as f:
        return {line.strip() for line in f if line.strip() and not line.strip().startswith("#")}


def select_import_candidates(
    results: List[RuleResult],
    import_dir: str,
    limit: Optional[int] = None,
    allow_path: Optional[str] = None,
    require_selector: bool = True,
) -> List[RuleResult]:
    """Pick a curated (never bulk) subset of the clean bucket to import.

    Raises ValueError if `require_selector` is set and neither --limit nor
    --allow narrows the selection — the guard against flooding rules/sigma/
    with the entire clean bucket in one shot.
    """
    clean = [r for r in results if r.bucket == "clean"]

    allowed = None
    if allow_path:
        allowed = _load_allowlist(allow_path)
        clean = [r for r in clean if r.uuid in allowed or os.path.basename(r.source_path) in allowed]

    if require_selector and limit is None and not allowed:
        raise ValueError(
            "Refusing to import the entire clean bucket in one shot. "
            "Pass --limit N and/or --allow <file> to curate a selection."
        )

    clean = sorted(clean, key=lambda r: r.source_path)
    if limit is not None:
        clean = clean[:limit]

    existing = _existing_import_uuids(import_dir)
    return [r for r in clean if r.uuid not in existing]


def apply_import(candidates: List[RuleResult], import_dir: str, ref: str, sha: str, repo_url: str) -> None:
    os.makedirs(import_dir, exist_ok=True)
    for r in candidates:
        dest = os.path.join(import_dir, os.path.basename(r.source_path))
        header = _provenance_header(r.source_path, ref, sha, repo_url)
        with open(dest, "w") as f:
            f.write(header + r.yaml_text)
        logger.info(f"Imported {dest}")


# --- CLI -----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sigmahq_coverage.py",
        description="Fetch a scoped SigmaHQ slice, report compiler coverage, optionally import clean rules.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    p_fetch = sub.add_parser("fetch", help="Sparse-clone the pinned SigmaHQ scope into the cache dir.")
    p_fetch.add_argument("--ref", default=None, help="SigmaHQ tag/commit to pin (default: pipeline.yaml sigmahq.pinned_ref).")
    p_fetch.add_argument("--force", action="store_true", help="Refetch even if the cache is already at --ref.")

    p_report = sub.add_parser("report", help="Compile-check the scope and write docs/COVERAGE.md.")
    p_report.add_argument("--ref", default=None)
    p_report.add_argument("--json", dest="json_out", default=None, help="Also write a machine-readable JSON report to this path.")

    p_import = sub.add_parser("import", help="Copy a curated selection of clean rules into rules/sigma/.")
    p_import.add_argument("--ref", default=None)
    p_import.add_argument("--apply", action="store_true", help="Actually write files (default is dry-run).")
    p_import.add_argument("--limit", type=int, default=None, help="Cap the number of rules imported.")
    p_import.add_argument("--allow", default=None, help="Path to a file of UUIDs/filenames to restrict import to.")

    return p


def main() -> None:
    args = build_parser().parse_args()
    cfg = load_sigmahq_config()
    ref = args.ref or cfg["pinned_ref"]

    if args.command == "fetch":
        fetch(ref, cfg["cache_dir"], cfg["repo_url"], cfg["scope_paths"], force=args.force)
        return

    # report / import both need the scope fetched first.
    fetch(ref, cfg["cache_dir"], cfg["repo_url"], cfg["scope_paths"], force=False)
    results = classify_all(cfg["cache_dir"], cfg["scope_paths"])
    sha = current_sha(cfg["cache_dir"])

    if args.command == "report":
        generated_on = datetime.now(timezone.utc).date().isoformat()
        md = render_report(results, ref, sha, cfg["repo_url"], generated_on)
        out_path = os.path.join("docs", "COVERAGE.md")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as f:
            f.write(md)
        logger.info(f"Wrote {out_path}")
        if args.json_out:
            with open(args.json_out, "w") as f:
                json.dump([r.to_json() for r in results], f, indent=2)
            logger.info(f"Wrote {args.json_out}")
        return

    if args.command == "import":
        try:
            candidates = select_import_candidates(
                results, cfg["import_dir"], limit=args.limit, allow_path=args.allow,
                require_selector=args.apply,
            )
        except ValueError as e:
            logger.error(str(e))
            sys.exit(1)

        if not args.apply:
            logger.info(f"{len(candidates)} candidate(s) for import (dry-run, pass --apply to write):")
            for r in candidates:
                logger.info(f"  {r.source_path} — {r.title}")
            return

        apply_import(candidates, cfg["import_dir"], ref, sha, cfg["repo_url"])
        logger.info(f"Imported {len(candidates)} rule(s) into {cfg['import_dir']}")


if __name__ == "__main__":
    main()
