import os
from scripts.check_rule_ids import validate_pipeline

def test_pipeline_catches_errors():
    """
    Ensures check_rule_ids.py correctly identifies structural
    and linkage errors in the XML/YAML fixtures.
    """
    fixture_dir = os.path.join("tests", "fixtures")
    
    # Run the validation against the fixtures directory
    errors = validate_pipeline(fixture_dir)
    
    # We expect multiple errors from our bad_wazuh.xml
    assert len(errors) > 0, "Pipeline failed to catch broken fixtures!"
    
    error_text = " ".join(errors)
    assert "Reserved ID Violation" in error_text, "Failed to catch rule ID < 100000"
    assert "Orphaned XML" in error_text, "Failed to catch missing sigma_uuid"
