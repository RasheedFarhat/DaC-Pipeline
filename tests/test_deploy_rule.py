import sys
import os
import pytest
import requests
import responses
from unittest.mock import patch

# Add the scripts directory to the path so we can import our deployment script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts')))
from deploy_rule import safe_api_request, deploy_rules, Settings, authed_request

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


# --- Bundle guard: never deploy an empty or partial ruleset ----------------------

def _settings(wazuh_dir):
    return Settings(wazuh_user="x", wazuh_password="x", wazuh_dir=wazuh_dir)


def test_deploy_rules_aborts_when_a_file_has_no_group(tmp_path):
    """A file with no parseable <group> would silently drop a rule; deploy must halt."""
    build = tmp_path / "build"
    build.mkdir()
    (build / "junk.xml").write_text("<notgroup/>")
    with pytest.raises(SystemExit):
        deploy_rules("OFFLINE_DRY_RUN_TOKEN", _settings(str(build)), False, dry_run=True)


def test_deploy_rules_aborts_on_partial_bundle(tmp_path):
    """If only some files bundle, abort rather than deploy an incomplete ruleset."""
    build = tmp_path / "build"
    build.mkdir()
    (build / "good.xml").write_text('<group name="x"><rule id="200001"/></group>')
    (build / "bad.xml").write_text("<notgroup/>")
    with pytest.raises(SystemExit):
        deploy_rules("OFFLINE_DRY_RUN_TOKEN", _settings(str(build)), False, dry_run=True)


def test_deploy_rules_bundles_complete_set(tmp_path):
    """When every file has a <group>, dry-run bundling succeeds."""
    build = tmp_path / "build"
    build.mkdir()
    (build / "r1.xml").write_text('<group name="x">\n  <rule id="200001" level="10"/>\n</group>')
    (build / "r2.xml").write_text('<group name="y">\n  <rule id="200002" level="10"/>\n</group>')
    assert deploy_rules("OFFLINE_DRY_RUN_TOKEN", _settings(str(build)), False, dry_run=True) is True


@responses.activate
def test_deploy_rules_put_includes_overwrite_true(tmp_path):
    """Without overwrite=true, the Wazuh API 200s but silently skips the write when the
    bundle file already exists (confirmed against a live manager: HTTP 200, body
    'error': 1, file on disk untouched). The PUT must always request overwrite=true."""
    build = tmp_path / "build"
    build.mkdir()
    (build / "r1.xml").write_text('<group name="x">\n  <rule id="200001" level="10"/>\n</group>')

    bundle_url = "https://localhost:55000/rules/files/sigma_custom_rules.xml"
    responses.add(responses.PUT, bundle_url, json={"error": 0}, status=200)

    assert deploy_rules("TOKEN", _settings(str(build)), False, dry_run=False) is True
    assert len(responses.calls) == 1
    assert responses.calls[0].request.url == bundle_url + "?overwrite=true"


# --- 401 token refresh -----------------------------------------------------------

RULES_URL = "https://localhost:55000/rules/files/x.xml"
AUTH_URL = "https://localhost:55000/security/user/authenticate"


@responses.activate
def test_authed_request_refreshes_token_on_401():
    """On a 401 the call re-authenticates once, retries, and returns the new token."""
    responses.add(responses.PUT, RULES_URL, status=401)
    responses.add(responses.GET, AUTH_URL, json={"data": {"token": "NEWTOKEN"}}, status=200)
    responses.add(responses.PUT, RULES_URL, status=200)

    settings = Settings(wazuh_user="u", wazuh_password="p")
    resp, token = authed_request("PUT", RULES_URL, settings, False, "OLDTOKEN", data="x")

    assert resp.status_code == 200
    assert token == "NEWTOKEN"
    assert len(responses.calls) == 3  # failed PUT, auth GET, retried PUT
    assert responses.calls[0].request.headers["Authorization"] == "Bearer OLDTOKEN"
    assert responses.calls[2].request.headers["Authorization"] == "Bearer NEWTOKEN"


@responses.activate
def test_authed_request_reauthenticates_only_once():
    """A second 401 after re-auth is propagated, not retried again."""
    responses.add(responses.PUT, RULES_URL, status=401)
    responses.add(responses.GET, AUTH_URL, json={"data": {"token": "NEWTOKEN"}}, status=200)
    responses.add(responses.PUT, RULES_URL, status=401)

    settings = Settings(wazuh_user="u", wazuh_password="p")
    with pytest.raises(requests.exceptions.HTTPError):
        authed_request("PUT", RULES_URL, settings, False, "OLDTOKEN", data="x")
    assert len(responses.calls) == 3  # PUT, auth, PUT — no further retry


@responses.activate
def test_authed_request_does_not_reauth_on_non_401():
    """A non-401 error surfaces without any re-authentication attempt."""
    responses.add(responses.PUT, RULES_URL, status=403)

    settings = Settings(wazuh_user="u", wazuh_password="p")
    with pytest.raises(requests.exceptions.HTTPError):
        authed_request("PUT", RULES_URL, settings, False, "OLDTOKEN", data="x")
    assert len(responses.calls) == 1  # no auth call
