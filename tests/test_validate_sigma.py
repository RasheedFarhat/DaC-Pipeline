import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from validate_sigma import run_pysigma_validation

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')

def test_sigma_syntax_validation():
    """Validates that the pipeline catches invalid Sigma rules."""
    errors = run_pysigma_validation(FIXTURE_DIR)
    assert len(errors) > 0, "Expected validation errors for the bad fixture, but got none"
