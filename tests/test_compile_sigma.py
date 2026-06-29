import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from sigma.collection import SigmaCollection
from compile_sigma import evaluate_ast, extract_mitre_techniques, template

WIN_CMD = "win.eventdata.commandLine"
WIN_IMG = "win.eventdata.image"


def _compile(detection: str):
    """Build a Sigma rule with the given detection block and return evaluate_ast output."""
    yaml_text = (
        "title: test\n"
        "id: 00000000-0000-0000-0000-000000000000\n"
        "logsource:\n"
        "    category: process_creation\n"
        "    product: windows\n"
        "detection:\n"
        f"{detection}\n"
    )
    rule = SigmaCollection.from_yaml(yaml_text).rules[0]
    return evaluate_ast(rule.detection.parsed_condition[0].parsed, rule)


# Each field maps to a LIST of literals, so expected values are lists.

# --- Operator semantics: contains / startswith / endswith / exact ---------------

def test_contains_is_unanchored():
    res = _compile("    sel:\n        CommandLine|contains: foo\n    condition: sel")
    assert res == [{WIN_CMD: [{"pattern": "(?i).*foo.*", "negate": False}]}]


def test_startswith_anchors_start_only():
    res = _compile("    sel:\n        CommandLine|startswith: foo\n    condition: sel")
    assert res == [{WIN_CMD: [{"pattern": "(?i)^foo.*", "negate": False}]}]


def test_endswith_anchors_end_only():
    res = _compile("    sel:\n        Image|endswith: '\\foo.exe'\n    condition: sel")
    expected = "(?i).*" + re.escape("\\foo.exe") + "$"
    assert res == [{WIN_IMG: [{"pattern": expected, "negate": False}]}]


def test_exact_match_is_fully_anchored():
    res = _compile("    sel:\n        CommandLine: foo\n    condition: sel")
    assert res == [{WIN_CMD: [{"pattern": "(?i)^foo$", "negate": False}]}]


# --- AND / OR -------------------------------------------------------------------

def test_and_distinct_fields_in_one_clause():
    res = _compile(
        "    sel:\n"
        "        CommandLine|contains: foo\n"
        "        Image|endswith: bar.exe\n"
        "    condition: sel"
    )
    assert len(res) == 1
    clause = res[0]
    assert set(clause) == {WIN_CMD, WIN_IMG}
    assert all(lit["negate"] is False for lits in clause.values() for lit in lits)


def test_and_same_field_merges_with_lookaheads():
    res = _compile(
        "    sel:\n"
        "        CommandLine|contains|all:\n"
        "            - foo\n"
        "            - bar\n"
        "    condition: sel"
    )
    assert res == [{WIN_CMD: [{"pattern": "(?=.*(?i).*foo.*)(?=.*(?i).*bar.*)", "negate": False}]}]


def test_or_produces_separate_clauses():
    res = _compile(
        "    sel:\n"
        "        CommandLine|contains:\n"
        "            - foo\n"
        "            - bar\n"
        "    condition: sel"
    )
    assert res == [
        {WIN_CMD: [{"pattern": "(?i).*foo.*", "negate": False}]},
        {WIN_CMD: [{"pattern": "(?i).*bar.*", "negate": False}]},
    ]


# --- NOT and De Morgan ----------------------------------------------------------

def test_not_single_leaf_sets_negate():
    res = _compile("    sel:\n        CommandLine|contains: foo\n    condition: not sel")
    assert res == [{WIN_CMD: [{"pattern": "(?i).*foo.*", "negate": True}]}]


def test_not_over_and_becomes_or_of_negations():
    # De Morgan: NOT(A AND B) == (NOT A) OR (NOT B) -> two single-field clauses
    res = _compile(
        "    sel:\n"
        "        CommandLine|contains: foo\n"
        "        Image|endswith: bar.exe\n"
        "    condition: not sel"
    )
    assert len(res) == 2
    assert all(len(clause) == 1 for clause in res)
    assert {WIN_CMD: [{"pattern": "(?i).*foo.*", "negate": True}]} in res
    assert {WIN_IMG: [{"pattern": "(?i).*bar\\.exe$", "negate": True}]} in res


def test_not_over_or_becomes_and_of_negations():
    # De Morgan: NOT(A OR B) == (NOT A) AND (NOT B) -> one clause, both negated
    res = _compile(
        "    selA:\n"
        "        CommandLine|contains: foo\n"
        "    selB:\n"
        "        Image|endswith: bar.exe\n"
        "    condition: not (selA or selB)"
    )
    assert len(res) == 1
    clause = res[0]
    assert clause[WIN_CMD] == [{"pattern": "(?i).*foo.*", "negate": True}]
    assert clause[WIN_IMG] == [{"pattern": "(?i).*bar\\.exe$", "negate": True}]


def test_not_over_same_field_or_uses_negated_alternation():
    # NOT(foo OR bar) on one field -> one negated field matching neither
    res = _compile(
        "    sel:\n"
        "        CommandLine|contains:\n"
        "            - foo\n"
        "            - bar\n"
        "    condition: not sel"
    )
    assert res == [{WIN_CMD: [{"pattern": "(?:(?i).*foo.*)|(?:(?i).*bar.*)", "negate": True}]}]


def test_double_negation_returns_positive():
    res = _compile("    sel:\n        CommandLine|contains: foo\n    condition: not (not sel)")
    assert res == [{WIN_CMD: [{"pattern": "(?i).*foo.*", "negate": False}]}]


def test_mixed_polarity_emits_two_field_literals():
    # `selection and not filter` on the SAME field -> a positive literal plus a
    # negated one, kept as two <field> elements (Wazuh ANDs them).
    res = _compile(
        "    selA:\n"
        "        CommandLine|contains: foo\n"
        "    selB:\n"
        "        CommandLine|contains: bar\n"
        "    condition: selA and not selB"
    )
    assert len(res) == 1
    lits = res[0][WIN_CMD]
    assert len(lits) == 2
    assert {"pattern": "(?i).*foo.*", "negate": False} in lits
    assert {"pattern": "(?i).*bar.*", "negate": True} in lits


# --- Template: negate="yes" rendering -------------------------------------------

def _render(fields):
    return template.render(
        product="windows", service="", rule_id="uuid", wazuh_id="200099",
        wazuh_level=10, parent_group="sysmon_event1",
        fields=fields, title="t", tags=[],
    )


def test_negated_field_renders_negate_yes():
    xml = _render({WIN_CMD: [{"pattern": ".*foo.*", "negate": True}]})
    assert 'negate="yes"' in xml
    assert 'type="pcre2"' in xml
    assert ".*foo.*" in xml


def test_positive_field_omits_negate_attribute():
    xml = _render({WIN_CMD: [{"pattern": ".*foo.*", "negate": False}]})
    assert "negate=" not in xml


def test_mixed_polarity_renders_two_field_elements():
    xml = _render({WIN_CMD: [
        {"pattern": ".*foo.*", "negate": False},
        {"pattern": ".*bar.*", "negate": True},
    ]})
    assert xml.count('name="win.eventdata.commandLine"') == 2
    assert 'negate="yes"' in xml


# --- MITRE technique extraction -------------------------------------------------

def test_mitre_keeps_and_uppercases_techniques():
    assert extract_mitre_techniques(["attack.t1105"]) == ["T1105"]


def test_mitre_keeps_subtechniques():
    assert extract_mitre_techniques(["attack.t1070.003"]) == ["T1070.003"]


def test_mitre_drops_tactics_and_other_namespaces():
    tags = ["attack.command_and_control", "attack.defense_evasion", "attack.g0016"]
    assert extract_mitre_techniques(tags) == []


def test_mitre_mixed_tags():
    tags = ["attack.command_and_control", "attack.t1105", "attack.t1070.003", "attack.g0016"]
    assert extract_mitre_techniques(tags) == ["T1105", "T1070.003"]


# --- Case-insensitivity (regression for the casing-evasion false negative) -------

def _compile_repo_rule(filename: str):
    """Compile a real shipped Sigma rule from rules/sigma/ and return its clauses."""
    path = os.path.join(os.path.dirname(__file__), "..", "rules", "sigma", filename)
    with open(path) as f:
        rule = SigmaCollection.from_yaml(f.read()).rules[0]
    return evaluate_ast(rule.detection.parsed_condition[0].parsed, rule)


def test_compiled_certutil_rule_matches_any_casing():
    """Sigma string matching is case-insensitive by default; the compiled Wazuh
    pcre2 pattern must fire on any casing of certutil.exe. Without an inline (?i)
    flag, `CertUtil.exe` / `CERTUTIL.EXE` evade the rule — a trivial, silent
    false negative. This asserts against the actual shipped detection.
    """
    clauses = _compile_repo_rule("sysmon_certutil_download.yml")
    image_patterns = [lit["pattern"] for clause in clauses for lit in clause.get(WIN_IMG, [])]
    assert image_patterns, "expected an Image-field literal in the compiled certutil rule"
    pattern = image_patterns[0]

    for sample in (
        r"C:\Windows\System32\certutil.exe",
        r"C:\Windows\System32\CertUtil.exe",
        r"C:\Windows\System32\CERTUTIL.EXE",
    ):
        assert re.search(pattern, sample), f"{sample!r} evaded pattern {pattern!r}"
