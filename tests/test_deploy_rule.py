import sys
import os
import pytest
import requests
import responses
from unittest.mock import patch

# Add the scripts directory to the path so we can import our deployment script
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts')))
from deploy_rule import safe_api_request, deploy_rules, reconcile_state, Settings, authed_request, get_token

# --- Constants for Testing ---
TEST_URL = 'https://localhost:55000/test_endpoint'


# --- Dry-run must work with zero configured credentials ---------------------------
# It never authenticates for real, so it shouldn't need real (or even placeholder)
# secrets. Previously Settings(wazuh_user=..., wazuh_password=...) had no defaults,
# so building Settings() at all raised a Pydantic ValidationError before dry-run
# ever got a chance to run -- confirmed against a clean env (env -i, no .env file).

def _settings_no_credentials() -> Settings:
    # _env_file=None disables pydantic-settings' .env lookup for this instance --
    # without it, a real local .env (gitignored, present on dev machines) would
    # leak real credentials into this "nothing configured" test and make it flaky.
    return Settings(_env_file=None)  # type: ignore[call-arg]


def test_settings_builds_with_no_credentials_configured():
    """Settings() must not raise just because no credentials are configured --
    that's the normal, expected state for dry-run."""
    settings = _settings_no_credentials()
    assert settings.wazuh_user is None
    assert settings.wazuh_password is None


@responses.activate
def test_get_token_dry_run_without_credentials_never_touches_network():
    """No WAZUH_USER/WAZUH_PASSWORD + dry-run must short-circuit straight to the
    offline sentinel token, without attempting any HTTP call at all."""
    settings = _settings_no_credentials()
    token = get_token(settings, tls_verify=True, dry_run=True)
    assert token == "OFFLINE_DRY_RUN_TOKEN"
    assert len(responses.calls) == 0


def test_get_token_real_deploy_without_credentials_exits_with_clear_error():
    """A real (non-dry-run) deploy still can't proceed without credentials -- but
    it must fail with a clear, explicit error instead of a bare Pydantic
    ValidationError surfacing from deep inside Settings() construction."""
    settings = _settings_no_credentials()
    with pytest.raises(SystemExit):
        get_token(settings, tls_verify=True, dry_run=False)

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
def test_deploy_rules_bundle_preserves_distinct_group_names(tmp_path):
    """Bundling used to collapse every rule into one generic "custom_sigma" group,
    silently discarding each rule's original product/service membership (e.g.
    "windows, custom_sigma" vs "linux, custom_sigma") -- confirmed live that this
    broke group:windows / group:linux filtering post-deploy. The bundle must emit
    one <group name=...> block per distinct name, not collapse them."""
    build = tmp_path / "build"
    build.mkdir()
    (build / "r1.xml").write_text('<group name="windows, custom_sigma">\n  <rule id="200001" level="10"/>\n</group>')
    (build / "r2.xml").write_text('<group name="linux, custom_sigma">\n  <rule id="200002" level="10"/>\n</group>')
    (build / "r3.xml").write_text('<group name="windows, custom_sigma">\n  <rule id="200003" level="10"/>\n</group>')

    bundle_url = "https://localhost:55000/rules/files/sigma_custom_rules.xml"
    responses.add(responses.PUT, bundle_url, json={"error": 0}, status=200)

    assert deploy_rules("TOKEN", _settings(str(build)), False, dry_run=False) is True

    sent_xml = responses.calls[0].request.body
    assert isinstance(sent_xml, str)
    assert sent_xml.count('<group name="windows, custom_sigma">') == 1
    assert sent_xml.count('<group name="linux, custom_sigma">') == 1
    assert 'id="200001"' in sent_xml and 'id="200002"' in sent_xml and 'id="200003"' in sent_xml
    # Both rules 200001 and 200003 share the windows group -- must land in the SAME
    # block, not two separate "windows, custom_sigma" blocks.
    windows_block = sent_xml.split('<group name="windows, custom_sigma">')[1].split('</group>')[0]
    assert 'id="200001"' in windows_block and 'id="200003"' in windows_block


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


@responses.activate
def test_deploy_rules_put_body_error_is_not_treated_as_success(tmp_path):
    """overwrite=true fixes the "already exists" no-op, but Wazuh can still 200 a PUT
    with a body-level failure for other reasons (confirmed live: this is the same
    HTTP-200-but-body-says-error shape). deploy_rules must not log success or return
    True when that happens."""
    build = tmp_path / "build"
    build.mkdir()
    (build / "r1.xml").write_text('<group name="x">\n  <rule id="200001" level="10"/>\n</group>')

    bundle_url = "https://localhost:55000/rules/files/sigma_custom_rules.xml"
    responses.add(
        responses.PUT, bundle_url, status=200,
        json={"error": 1, "total_failed_items": 1, "message": "Rule content is invalid"},
    )

    assert deploy_rules("TOKEN", _settings(str(build)), False, dry_run=False) is False


# --- Orphan reconciliation: DELETE must check the body, not just HTTP status -----

RULES_LIST_URL = "https://localhost:55000/rules/files"


@responses.activate
def test_reconcile_state_deletes_orphaned_file_on_real_success():
    """Sanity check: a genuinely successful DELETE (200, error:0) is still logged
    and doesn't raise -- the body check must not reject legitimate successes."""
    responses.add(
        responses.GET, RULES_LIST_URL, status=200,
        json={"data": {"affected_items": [{"filename": "orphan.xml", "path": "etc/rules/orphan.xml"}]}},
    )
    delete_url = "https://localhost:55000/rules/files/orphan.xml"
    responses.add(responses.DELETE, delete_url, status=200, json={"error": 0, "total_failed_items": 0})

    reconcile_state("TOKEN", _settings("/nonexistent"), False, dry_run=False)

    delete_calls = [c for c in responses.calls if c.request.method == "DELETE"]
    assert len(delete_calls) == 1


@responses.activate
def test_reconcile_state_does_not_log_success_when_delete_body_reports_failure():
    """DELETE of a file that's already gone (or fails server-side) still returns
    HTTP 200 (confirmed against a live manager: body 'error': 1, file untouched).
    reconcile_state must not claim the orphan was deleted when it wasn't."""
    responses.add(
        responses.GET, RULES_LIST_URL, status=200,
        json={"data": {"affected_items": [{"filename": "orphan.xml", "path": "etc/rules/orphan.xml"}]}},
    )
    delete_url = "https://localhost:55000/rules/files/orphan.xml"
    responses.add(
        responses.DELETE, delete_url, status=200,
        json={"error": 1, "total_failed_items": 1,
              "failed_items": [{"error": {"message": "File does not exist"}}]},
    )

    with patch("deploy_rule.logger") as mock_logger:
        reconcile_state("TOKEN", _settings("/nonexistent"), False, dry_run=False)

        success_logs = [c for c in mock_logger.info.call_args_list if "Deleted orphaned rule" in str(c)]
        assert success_logs == [], "must not log a false success for a delete that failed"
        assert mock_logger.error.called, "the body-level failure must surface as an error"


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
