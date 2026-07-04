import os

from scripts.check_rule_ids import validate_pipeline

VALID_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OTHER_UUID = "11111111-2222-3333-4444-555555555555"


def _write_sigma(dirpath, name="rule.yml", uuid=VALID_UUID):
    path = dirpath / name
    path.write_text(f"title: test rule\nid: {uuid}\n")
    return path


def _write_xml(dirpath, name, rule_id, uuid=VALID_UUID, with_comment=True):
    comment = f"<!-- sigma_uuid:{uuid} -->" if with_comment else ""
    path = dirpath / name
    path.write_text(
        f'<group name="x">\n'
        f'  <rule id="{rule_id}" level="10">\n'
        f'    {comment}\n'
        f'    <description>test</description>\n'
        f'  </rule>\n'
        f'</group>\n'
    )
    return path


def test_pipeline_catches_errors():
    """The deliberately-broken checked-in fixtures must trip the validator."""
    fixture_dir = os.path.join("tests", "fixtures")

    errors = validate_pipeline(fixture_dir)

    assert len(errors) > 0, "Pipeline failed to catch broken fixtures!"
    error_text = " ".join(errors)
    assert "Reserved ID Violation" in error_text, "Failed to catch rule ID < 200000"
    assert "Orphaned XML" in error_text, "Failed to catch missing sigma_uuid"


def test_valid_pair_produces_no_errors(tmp_path):
    """A well-formed Sigma rule + linked XML with an ID >= 200000 must pass clean."""
    _write_sigma(tmp_path)
    _write_xml(tmp_path, "rule_200001.xml", 200001)

    assert validate_pipeline(str(tmp_path)) == []


def test_reserved_id_rejected(tmp_path):
    """IDs below 200000 collide with Wazuh built-in / reserved space."""
    _write_sigma(tmp_path)
    _write_xml(tmp_path, "rule_1000.xml", 1000)

    errors = validate_pipeline(str(tmp_path))
    assert any("Reserved ID Violation" in e for e in errors)


def test_non_integer_id_rejected(tmp_path):
    _write_sigma(tmp_path)
    _write_xml(tmp_path, "rule_bad.xml", "not-a-number")

    errors = validate_pipeline(str(tmp_path))
    assert any("Invalid ID Format" in e for e in errors)


def test_duplicate_wazuh_id_across_files_rejected(tmp_path):
    """Two XML files claiming the same Wazuh ID would make the manager reject the
    ruleset (or worse, silently shadow one rule) -- must fail validation."""
    _write_sigma(tmp_path, "a.yml", VALID_UUID)
    _write_sigma(tmp_path, "b.yml", OTHER_UUID)
    _write_xml(tmp_path, "a_200001.xml", 200001, VALID_UUID)
    _write_xml(tmp_path, "b_200001.xml", 200001, OTHER_UUID)

    errors = validate_pipeline(str(tmp_path))
    assert any("Duplicate Wazuh XML ID" in e for e in errors)


def test_dangling_uuid_rejected(tmp_path):
    """XML referencing a Sigma UUID that no longer exists is an orphan -- the
    compiled artifact outlived its source of truth."""
    _write_sigma(tmp_path, uuid=VALID_UUID)
    _write_xml(tmp_path, "rule_200001.xml", 200001, uuid=OTHER_UUID)

    errors = validate_pipeline(str(tmp_path))
    assert any("Orphaned XML (Dangling)" in e for e in errors)


def test_missing_uuid_comment_rejected(tmp_path):
    """Every compiled XML must declare its Sigma parent via the sigma_uuid comment."""
    _write_sigma(tmp_path)
    _write_xml(tmp_path, "rule_200001.xml", 200001, with_comment=False)

    errors = validate_pipeline(str(tmp_path))
    assert any("Orphaned XML (Omission)" in e for e in errors)


def test_duplicate_sigma_uuid_rejected(tmp_path):
    """Two Sigma rules sharing one UUID would fight over the same registry entry."""
    _write_sigma(tmp_path, "a.yml", VALID_UUID)
    _write_sigma(tmp_path, "b.yml", VALID_UUID)
    _write_xml(tmp_path, "a_200001.xml", 200001)

    errors = validate_pipeline(str(tmp_path))
    assert any("Duplicate Sigma UUID" in e for e in errors)
