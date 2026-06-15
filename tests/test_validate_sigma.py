import os
from scripts.validate_sigma import validate_sigma_rules

def test_sigma_syntax_validation():
    """
    Ensures validate_sigma.py correctly identifies malformed Sigma YAML.
    """
    fixture_dir = os.path.join("tests", "fixtures")
    errors = validate_sigma_rules(fixture_dir)
    
    assert len(errors) > 0, "Sigma validation failed to catch broken syntax!"
    error_text = " ".join(errors)
    
    # Target the specific pySigma schema violation
    assert "Sigma rule must have a log source" in error_text, "Failed to catch the missing logsource block"
