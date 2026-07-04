import os
import sys

import pytest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from sigmahq_coverage import (
    RuleResult,
    apply_import,
    classify_rule_text,
    render_report,
    select_import_candidates,
)


def _rule_yaml(detection: str, rule_id: str = "11111111-1111-1111-1111-111111111111", title: str = "test rule") -> str:
    return (
        f"title: {title}\n"
        f"id: {rule_id}\n"
        "logsource:\n"
        "    category: process_creation\n"
        "    product: windows\n"
        "detection:\n"
        f"{detection}\n"
    )


# --- Bucketing: clean / unmapped / each failure type -----------------------------

def test_clean_rule_is_bucketed_clean():
    yaml_text = _rule_yaml(
        "    sel:\n        CommandLine|contains: foo\n    condition: sel"
    )
    results = classify_rule_text(yaml_text, "proc_creation_win_clean.yml")
    assert len(results) == 1
    assert results[0].bucket == "clean"
    assert results[0].unmapped_fields == []


def test_unmapped_field_is_bucketed_and_listed():
    yaml_text = _rule_yaml(
        "    sel:\n        TotallyUnknownField|contains: foo\n    condition: sel"
    )
    results = classify_rule_text(yaml_text, "proc_creation_win_unmapped.yml")
    assert len(results) == 1
    assert results[0].bucket == "unmapped_field"
    assert results[0].unmapped_fields == ["TotallyUnknownField"]


def test_base64_modifier_bucketed_by_modifier_name():
    yaml_text = _rule_yaml(
        "    sel:\n        CommandLine|base64: whoami\n    condition: sel"
    )
    results = classify_rule_text(yaml_text, "proc_creation_win_b64.yml")
    assert results[0].bucket == "unsupported_modifier:base64"


def test_numeric_comparison_bucketed_by_value_type():
    yaml_text = _rule_yaml(
        "    sel:\n        DestinationPort|gt: 1024\n    condition: sel"
    )
    results = classify_rule_text(yaml_text, "proc_creation_win_numeric.yml")
    assert results[0].bucket == "unsupported_value_type:SigmaCompareExpression"


def test_fieldless_keyword_bucketed_as_keyword():
    yaml_text = _rule_yaml(
        "    keywords:\n        - evil\n    condition: keywords"
    )
    results = classify_rule_text(yaml_text, "proc_creation_win_keyword.yml")
    assert results[0].bucket == "unsupported_leaf:keyword"


def test_empty_value_bucketed_as_empty_value():
    yaml_text = _rule_yaml(
        "    sel:\n        CommandLine: ''\n    condition: sel"
    )
    results = classify_rule_text(yaml_text, "proc_creation_win_empty.yml")
    assert results[0].bucket == "empty_value"


def test_null_value_bucketed_as_null_value():
    yaml_text = _rule_yaml(
        "    sel:\n        CommandLine:\n    condition: sel"
    )
    results = classify_rule_text(yaml_text, "proc_creation_win_null.yml")
    assert results[0].bucket == "null_value"


def test_unparseable_yaml_bucketed_as_pysigma_parse_error():
    results = classify_rule_text("not: [valid, sigma", "broken.yml")
    assert results[0].bucket == "pysigma_parse_error"


def test_correlation_rule_bucketed_as_unsupported_rule_type():
    """A Sigma correlation rule has no detection AST to walk. It must land in its
    own bucket instead of crashing the classifier on a missing attribute -- and the
    ordinary detection rule sharing the same file must still classify normally."""
    yaml_text = (
        "title: Base rule\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "name: base\n"
        "logsource:\n"
        "    category: process_creation\n"
        "    product: windows\n"
        "detection:\n"
        "    sel:\n"
        "        CommandLine|contains: foo\n"
        "    condition: sel\n"
        "---\n"
        "title: Correlation rule\n"
        "id: 22222222-2222-2222-2222-222222222222\n"
        "correlation:\n"
        "    type: event_count\n"
        "    rules:\n"
        "        - base\n"
        "    timespan: 5m\n"
        "    condition:\n"
        "        gte: 10\n"
    )
    results = classify_rule_text(yaml_text, "proc_creation_win_corr.yml")
    buckets = {r.bucket for r in results}
    assert "clean" in buckets
    assert "unsupported_rule_type:SigmaCorrelationRule" in buckets


# --- Report rendering -------------------------------------------------------------

def test_render_report_headline_matches_counts():
    results = [
        RuleResult("a.yml", "A", "clean", ""),
        RuleResult("b.yml", "B", "unmapped_field", "Foo", unmapped_fields=["Foo"]),
        RuleResult("c.yml", "C", "unsupported_modifier:base64", "boom"),
    ]
    md = render_report(results, "r2026-04-01", "deadbeef", "https://github.com/SigmaHQ/sigma", "2026-07-01")
    assert "Coverage: 33.3% (1 / 3 rules compiled clean)" in md
    assert "`unsupported_modifier:base64` | 1" in md
    assert "`Foo` | 1" in md


def test_render_report_ranks_failure_buckets_by_frequency():
    results = [
        RuleResult("a.yml", "A", "unsupported_modifier:base64", "x"),
        RuleResult("b.yml", "B", "unsupported_modifier:base64", "x"),
        RuleResult("c.yml", "C", "null_value", "x"),
    ]
    md = render_report(results, "ref", "sha", "url", "2026-07-01")
    base64_idx = md.index("unsupported_modifier:base64")
    null_idx = md.index("null_value")
    assert base64_idx < null_idx  # higher count (2) listed before lower count (1)


# --- Import: curated selection, footgun guard, dedupe, provenance -----------------

def test_select_import_candidates_requires_selector_when_apply():
    results = [RuleResult("a.yml", "A", "clean", "", uuid="u1", yaml_text="title: A\n")]
    with pytest.raises(ValueError):
        select_import_candidates(results, "/nonexistent", require_selector=True)


def test_select_import_candidates_dry_run_does_not_require_selector():
    results = [RuleResult("a.yml", "A", "clean", "", uuid="u1", yaml_text="title: A\n")]
    candidates = select_import_candidates(results, "/nonexistent", require_selector=False)
    assert len(candidates) == 1


def test_select_import_candidates_respects_limit():
    results = [
        RuleResult(f"{c}.yml", c, "clean", "", uuid=c, yaml_text=f"title: {c}\n")
        for c in ("a", "b", "c")
    ]
    candidates = select_import_candidates(results, "/nonexistent", limit=2, require_selector=True)
    assert [c.source_path for c in candidates] == ["a.yml", "b.yml"]


def test_select_import_candidates_allow_filters_by_uuid_or_filename():
    results = [
        RuleResult("a.yml", "A", "clean", "", uuid="uuid-a", yaml_text="title: A\n"),
        RuleResult("b.yml", "B", "clean", "", uuid="uuid-b", yaml_text="title: B\n"),
    ]
    allow_path = "/tmp/allow_test.txt"
    with open(allow_path, "w") as f:
        f.write("uuid-a\n")
    try:
        candidates = select_import_candidates(results, "/nonexistent", allow_path=allow_path, require_selector=True)
        assert [c.source_path for c in candidates] == ["a.yml"]
    finally:
        os.remove(allow_path)


def test_select_import_candidates_dedupes_already_imported_uuid(tmp_path):
    import_dir = tmp_path / "sigmahq"
    import_dir.mkdir()
    (import_dir / "a.yml").write_text("id: uuid-a\ntitle: A\n")

    results = [
        RuleResult("a.yml", "A", "clean", "", uuid="uuid-a", yaml_text="title: A\n"),
        RuleResult("b.yml", "B", "clean", "", uuid="uuid-b", yaml_text="title: B\n"),
    ]
    candidates = select_import_candidates(results, str(import_dir), limit=10, require_selector=True)
    assert [c.source_path for c in candidates] == ["b.yml"]


def test_apply_import_writes_provenance_header(tmp_path):
    import_dir = tmp_path / "sigmahq"
    results = [RuleResult(
        "rules/windows/process_creation/proc_x.yml", "X", "clean", "",
        uuid="uuid-x", yaml_text="title: X\nid: uuid-x\n",
    )]
    apply_import(results, str(import_dir), "r2026-04-01", "deadbeef", "https://github.com/SigmaHQ/sigma")

    written = (import_dir / "proc_x.yml").read_text()
    assert "# Imported from SigmaHQ" in written
    assert "# Source path: rules/windows/process_creation/proc_x.yml" in written
    assert "# Pinned ref: r2026-04-01 (deadbeef)" in written
    assert "Detection Rule License (DRL) 1.1" in written
    assert written.endswith("title: X\nid: uuid-x\n")

    reparsed = yaml.safe_load(written)
    assert reparsed["id"] == "uuid-x"
