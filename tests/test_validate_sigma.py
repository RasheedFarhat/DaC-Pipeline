import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
from validate_sigma import run_pysigma_validation, run_backend_compilability_check

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), 'fixtures')
SIGMA_DIR = os.path.join(os.path.dirname(__file__), '..', 'rules', 'sigma')

def test_sigma_syntax_validation():
    """Validates that the pipeline catches invalid Sigma rules."""
    errors = run_pysigma_validation(FIXTURE_DIR)
    assert len(errors) > 0, "Expected validation errors for the bad fixture, but got none"


def test_backend_compilability_check_passes_on_real_rules():
    """Every shipped Sigma rule must convert cleanly through a real pySigma
    backend (Elasticsearch Lucene + sysmon pipeline) -- this is the check the
    README's compilability claim rests on, so it must actually pass on the
    real ruleset, not just on synthetic fixtures."""
    errors = run_backend_compilability_check(SIGMA_DIR)
    assert errors == []


def test_backend_compilability_check_rejects_broken_fixture():
    """The deliberately-broken fixture (missing logsource) must fail the
    backend conversion, proving this check isn't a silent no-op."""
    errors = run_backend_compilability_check(FIXTURE_DIR)
    assert len(errors) > 0
    assert "Backend compilability check failed" in errors[0]
