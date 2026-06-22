import sys
import os
import pytest
import requests
import responses
from unittest.mock import patch

# Add the scripts directory to the path so we can import our deployment script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts')))
from deploy_rule import safe_api_request

# --- Constants for Testing ---
TEST_URL = 'https://localhost:55000/test_endpoint'

@responses.activate
def test_safe_api_request_success():
    """Test that a standard 200 OK response works immediately."""
    responses.add(responses.GET, TEST_URL, json={'status': 'success'}, status=200)

    resp = safe_api_request('GET', TEST_URL, verify=False)

    assert resp.status_code == 200
    assert len(responses.calls) == 1

@patch('time.sleep', return_value=None)
@responses.activate
def test_safe_api_request_retry_on_429(mock_sleep):
    """
    Test the Rate Limit Survivor.
    Simulate the API throwing 429 (Too Many Requests) three times,
    and then succeeding with a 200 OK on the fourth try.
    """
    # Queue up the fake responses in order
    responses.add(responses.GET, TEST_URL, status=429)
    responses.add(responses.GET, TEST_URL, status=429)
    responses.add(responses.GET, TEST_URL, status=429)
    responses.add(responses.GET, TEST_URL, json={'status': 'recovered'}, status=200)

    # Execute the function. Tenacity should intercept the 429s and retry automatically.
    resp = safe_api_request('GET', TEST_URL, verify=False)

    # Prove that it eventually succeeded
    assert resp.status_code == 200

    # Prove that it actually took 4 attempts to get there
    assert len(responses.calls) == 4

@patch('time.sleep', return_value=None)
@responses.activate
def test_safe_api_request_max_retries_on_500(mock_sleep):
    """
    Test the Hard Crash.
    Simulate a dead server (500 Internal Server Error).
    Prove that tenacity gives up after exactly 5 tries and surfaces the real error.
    """
    # Tell the mock to endlessly return 500s
    responses.add(responses.GET, TEST_URL, status=500)

    # We expect the script to aggressively crash and raise the underlying HTTPError
    with pytest.raises(requests.exceptions.HTTPError):
        safe_api_request('GET', TEST_URL, verify=False)

    # Prove that tenacity stopped exactly at our configured limit (stop_after_attempt=5)
    assert len(responses.calls) == 5
