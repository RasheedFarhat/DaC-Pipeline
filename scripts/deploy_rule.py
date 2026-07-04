import os
import sys
import requests
import logging
import argparse
import yaml
from typing import Any, Dict, Set, Optional, Union, List, Tuple
from pydantic import Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception, before_sleep_log

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

BUNDLE_FILENAME = "sigma_custom_rules.xml"

# --- Strict Configuration Schema ---
class Settings(BaseSettings):
    wazuh_api_url: str = Field(default="https://localhost:55000")
    # Optional, not required: dry-run never authenticates for real (see get_token),
    # so it must be able to build a Settings object with zero configured credentials.
    # A real (non-dry-run) deploy still can't proceed without them -- enforced
    # explicitly in get_token(), which gives a clearer error than a bare Pydantic
    # ValidationError would.
    wazuh_user: Optional[str] = Field(default=None)
    wazuh_password: Optional[str] = Field(default=None)
    wazuh_ca_bundle: Optional[str] = Field(default=None)
    wazuh_verify_tls: bool = Field(default=True)

    wazuh_dir: str = Field(default="build/wazuh")
    agent_conf_path: str = Field(default="configs/agent.conf")
    target_group: str = Field(default="default")

    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    @field_validator("wazuh_verify_tls", mode="before")
    @classmethod
    def _empty_string_means_default(cls, v: Any) -> Any:
        # An unset GitHub Actions secret arrives as an empty-string env var.
        # Treat "" as "not configured" and keep the secure default (verify=True)
        # instead of crashing on a bool-parsing ValidationError.
        if isinstance(v, str) and v.strip() == "":
            return True
        return v

def load_settings() -> Settings:
    config_data: Dict[str, Any] = {}
    try:
        with open("pipeline.yaml", "r") as f:
            loaded = yaml.safe_load(f)
            if loaded:
                config_data['wazuh_dir'] = loaded.get('build', {}).get('wazuh_dir', 'build/wazuh')
                config_data['agent_conf_path'] = loaded.get('deploy', {}).get('agent_conf_path', 'configs/agent.conf')
                config_data['target_group'] = loaded.get('deploy', {}).get('target_group', 'default')
                config_data['wazuh_api_url'] = loaded.get('deploy', {}).get('api_url', 'https://localhost:55000')
    except FileNotFoundError:
        logger.warning("pipeline.yaml not found. Relying strictly on environment variables and defaults.")

    try:
        return Settings(**config_data)
    except ValidationError as e:
        logger.error(f"CRITICAL: Configuration Validation Failed! Missing or invalid environment variables.\n{e}")
        sys.exit(1)

def get_tls_strategy(settings: Settings) -> Union[bool, str]:
    if settings.wazuh_ca_bundle:
        # A configured-but-missing bundle must not silently fall back to the system
        # trust store: the operator asked for a specific CA, and proceeding without
        # it either fails confusingly later (self-signed manager) or "works" while
        # validating against roots the operator never chose.
        if not os.path.isfile(settings.wazuh_ca_bundle):
            logger.error(
                f"CRITICAL: WAZUH_CA_BUNDLE is set but the file does not exist: "
                f"{settings.wazuh_ca_bundle}"
            )
            sys.exit(1)
        return settings.wazuh_ca_bundle
    elif not settings.wazuh_verify_tls:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.warning("INSECURE MODE ACTIVATED: TLS certificate verification is disabled.")
        return False
    return True

def is_retryable_exception(exception: BaseException) -> bool:
    if isinstance(exception, requests.exceptions.HTTPError):
        status: int = exception.response.status_code
        return status == 429 or status >= 500
    return isinstance(exception, (requests.exceptions.ConnectionError, requests.exceptions.Timeout))

@retry(
    retry=retry_if_exception(is_retryable_exception),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    stop=stop_after_attempt(5),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True
)
def safe_api_request(method: str, url: str, **kwargs: Any) -> requests.Response:
    response: requests.Response = requests.request(method, url, **kwargs)
    response.raise_for_status()
    return response

def authed_request(
    method: str, url: str, settings: "Settings", tls_verify: Union[bool, str], token: str, **kwargs: Any
) -> Tuple[requests.Response, str]:
    """Issue an authenticated Wazuh API request, re-authenticating once on 401.

    The Wazuh JWT is short-lived (15 min by default), so a long deploy can outlive
    its token. On a 401 we re-authenticate exactly once and retry the call. The
    (possibly refreshed) token is returned alongside the response so callers can
    reuse it for later requests instead of forcing another round-trip. A second 401
    after re-auth is propagated rather than retried again.
    """
    headers: Dict[str, str] = dict(kwargs.pop("headers", {}))
    headers["Authorization"] = f"Bearer {token}"
    try:
        return safe_api_request(method, url, headers=headers, verify=tls_verify, **kwargs), token
    except requests.exceptions.HTTPError as e:
        if token == "OFFLINE_DRY_RUN_TOKEN" or e.response is None or e.response.status_code != 401:
            raise
        logger.warning("Wazuh API returned 401 (token likely expired). Re-authenticating once and retrying.")
        token = get_token(settings, tls_verify)
        headers["Authorization"] = f"Bearer {token}"
        return safe_api_request(method, url, headers=headers, verify=tls_verify, **kwargs), token

def assert_wazuh_result_ok(response: requests.Response, action: str) -> None:
    """Raise if the Wazuh API reported failure in the JSON body, even on HTTP 200.

    Wazuh's /rules/files/* endpoints (and others) can return HTTP 200 while the
    write/delete itself was skipped -- the only signal is the body's "error" /
    "total_failed_items" fields. Confirmed against a live manager: a PUT without
    overwrite=true, and a DELETE of a file that doesn't exist, both return 200 with
    "error": 1. raise_for_status() never sees this, so every /rules/files/* caller
    must check the body explicitly instead of trusting a 200 status.
    """
    try:
        body = response.json()
    except ValueError:
        return
    if body.get("error", 0) or body.get("total_failed_items", 0):
        raise requests.exceptions.RequestException(
            f"Wazuh API reported failure while {action}: {body.get('message', body)}"
        )

def get_token(settings: Settings, tls_verify: Union[bool, str], dry_run: bool = False) -> str:
    if not settings.wazuh_user or not settings.wazuh_password:
        if dry_run:
            logger.warning(
                "WAZUH_USER/WAZUH_PASSWORD not set. Dry-run never authenticates for "
                "real, so this is fine -- simulating without ever touching the network."
            )
            return "OFFLINE_DRY_RUN_TOKEN"
        logger.error("CRITICAL: WAZUH_USER and WAZUH_PASSWORD must be set for a real (non-dry-run) deploy.")
        sys.exit(1)

    logger.info("Authenticating to the Wazuh API...")
    url: str = f"{settings.wazuh_api_url}/security/user/authenticate"
    try:
        response: requests.Response = safe_api_request('GET', url, auth=(settings.wazuh_user, settings.wazuh_password), verify=tls_verify)
        logger.info("Authentication successful.")
        return str(response.json()['data']['token'])
    except requests.exceptions.RequestException as e:
        if dry_run:
            logger.warning(f"API unreachable ({e}). Falling back to OFFLINE dry-run mode.")
            return "OFFLINE_DRY_RUN_TOKEN"
        logger.error(f"CRITICAL: Network or HTTP error during authentication: {e}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"CRITICAL: Failed to parse JSON response during authentication: {e}")
        sys.exit(1)

def deploy_rules(token: str, settings: Settings, tls_verify: Union[bool, str], dry_run: bool = False) -> bool:
    logger.info(f"Scanning {settings.wazuh_dir} for rule files...")
    if not os.path.exists(settings.wazuh_dir):
        logger.error(f"CRITICAL: Directory {settings.wazuh_dir} not found. Did the compiler run?")
        sys.exit(1)

    xml_files = sorted([f for f in os.listdir(settings.wazuh_dir) if f.endswith(".xml")])
    if not xml_files:
        logger.error("CRITICAL: No XML rule files found in build directory.")
        sys.exit(1)

    # Bundle all rules into a single file to avoid Wazuh restart race condition.
    # Each compiled file already carries its own product/service group (e.g.
    # "windows, custom_sigma" -- see templates/wazuh_rule.xml.j2), which Wazuh uses
    # for group:windows / group:linux filtering downstream. Collapsing everything
    # into one generic "custom_sigma" group on bundling silently discarded that
    # membership for all rules (confirmed against a live manager). Wazuh natively
    # supports multiple top-level <group> elements in one rules file (its own
    # ruleset/rules/*.xml ship this way), so instead of one master group we emit
    # one <group name="X"> block per distinct group name, preserving each rule's
    # original membership.
    import re as _re
    from collections import defaultdict
    groups: Dict[str, List[str]] = defaultdict(list)
    bundled_count = 0
    for filename in xml_files:
        filepath = os.path.join(settings.wazuh_dir, filename)
        with open(filepath, 'r') as f:
            file_content = f.read()
        # Capture both the group name and the inner content between the tags.
        match = _re.search(r'<group\s+name="([^"]*)"[^>]*>(.*?)</group>', file_content, _re.DOTALL)
        if match:
            group_name, inner_content = match.group(1), match.group(2)
            groups[group_name].append(f'  <!-- Source: {filename} -->\n{inner_content.strip()}')
            bundled_count += 1
        else:
            logger.error(f"CRITICAL: {filename} has no parseable <group name=\"...\"> block; refusing to bundle.")

    # A bundle that dropped (or found zero) rules would, once deployed and the manager
    # restarted, silently wipe the live ruleset. Halt before doing any damage.
    if bundled_count != len(xml_files):
        logger.error(
            f"CRITICAL: Only {bundled_count} of {len(xml_files)} rule files bundled. "
            "Aborting to avoid deploying an incomplete ruleset."
        )
        sys.exit(1)

    bundled_xml = '\n'.join(
        f'<group name="{name}">\n' + '\n'.join(blocks) + '\n</group>'
        for name, blocks in sorted(groups.items())
    )
    if dry_run:
        logger.info(f"[DRY RUN] Would deploy {len(xml_files)} rules bundled as {BUNDLE_FILENAME}")
        return True

    headers: Dict[str, str] = {'Content-Type': 'application/octet-stream'}

    # overwrite=true is required once BUNDLE_FILENAME already exists on the manager.
    # Without it, the Wazuh API returns HTTP 200 with an "error" field set in the body
    # and leaves the existing file untouched — raise_for_status() sees only the 200
    # and never notices the write was skipped, so every re-deploy after the first
    # silently no-ops (confirmed against a live manager: the file's on-disk content
    # and mtime are untouched by an overwrite-less PUT to an existing filename).
    url = f"{settings.wazuh_api_url}/rules/files/{BUNDLE_FILENAME}?overwrite=true"
    try:
        response, token = authed_request('PUT', url, settings, tls_verify, token, headers=headers, data=bundled_xml)
        # overwrite=true fixes the specific "file already exists" no-op above, but the
        # Wazuh API can 200 with a body-level failure for other reasons too (e.g. a
        # malformed bundle it rejects) -- check the body, don't trust the HTTP status alone.
        assert_wazuh_result_ok(response, f"deploying {BUNDLE_FILENAME}")
        logger.info(f"Successfully deployed {len(xml_files)} rules as {BUNDLE_FILENAME}")
    except requests.exceptions.RequestException as e:
        logger.error(f"ERROR: Network or API failure deploying bundle: {e}")
        return False

    return True

def reconcile_state(token: str, settings: Settings, tls_verify: Union[bool, str], dry_run: bool = False) -> bool:
    """Delete remote rules superseded or orphaned by this deploy.

    Returns True on success (including "nothing to do"), False if the remote
    state could not be read or any delete failed -- the caller must surface that
    as a failed deploy instead of exiting 0 with stale rules still live.
    """
    logger.info("Reconciling State (Detecting and deleting orphaned rules)...")

    if token == "OFFLINE_DRY_RUN_TOKEN":
        logger.info("[DRY RUN] API is offline. Skipping remote orphan reconciliation.")
        return True

    IGNORE_FILES: Set[str] = {"local_rules.xml"}
    try:
        response, token = authed_request('GET', f"{settings.wazuh_api_url}/rules/files", settings, tls_verify, token)
        resp_json: Dict[str, Any] = response.json()

        remote_custom_files: Set[str] = set()
        items: List[Dict[str, Any]] = resp_json.get('data', {}).get('affected_items', [])
        if not items:
            items = resp_json.get('data', {}).get('items', [])

        for item in items:
            path: str = item.get('path', '')
            filename: str = item.get('filename') or item.get('file', '')
            if filename and filename.endswith('.xml') and 'etc/rules' in path:
                remote_custom_files.add(filename)

        local_files: Set[str] = {BUNDLE_FILENAME}
        orphaned_files: Set[str] = (remote_custom_files - local_files) - IGNORE_FILES

        if not orphaned_files:
            logger.info("State matches. No orphaned rules to delete.")
            return True

        # Per-rule files from a previous (pre-bundle) deploy share their names with the
        # current build output, because rule IDs are stable via id_registry.json. They
        # are now superseded by the single bundle and MUST be deleted (otherwise their
        # rules double-fire alongside the bundle). Deleting them is an expected migration
        # step, so they bypass the blast-radius guard. Every other orphan is foreign
        # (hand-added, or left by a rule deleted from the repo) and stays gated.
        build_files: Set[str] = {f for f in os.listdir(settings.wazuh_dir) if f.endswith(".xml")} if os.path.exists(settings.wazuh_dir) else set()
        superseded: Set[str] = orphaned_files & build_files
        foreign: Set[str] = orphaned_files - build_files

        # --- SAFEGUARD (foreign rules only) ---
        DELETE_THRESHOLD = 5
        if len(foreign) > DELETE_THRESHOLD:
            if dry_run:
                logger.warning(f"[DRY RUN] WARNING: Would attempt to delete {len(foreign)} foreign rules, which exceeds the safety threshold of {DELETE_THRESHOLD}.")
            else:
                logger.error(f"CRITICAL: Foreign orphaned rule count ({len(foreign)}) exceeds the blast radius threshold of {DELETE_THRESHOLD}.")
                logger.error("Aborting deployment to prevent accidental purging of production rules.")
                sys.exit(1)
        # ------------------------------

        if superseded:
            logger.info(f"Cleaning up {len(superseded)} pre-bundle rule file(s) superseded by {BUNDLE_FILENAME}.")

        for filename in sorted(superseded | foreign):
            if dry_run:
                logger.info(f"[DRY RUN] Would DELETE orphaned rule: {filename}")
            else:
                resp, token = authed_request('DELETE', f"{settings.wazuh_api_url}/rules/files/{filename}", settings, tls_verify, token)
                # Same blind spot as the PUT bundle: DELETE of a file that's already
                # gone, or that fails server-side, still returns HTTP 200 (confirmed
                # against a live manager). Without this check we'd log "Deleted" for a
                # delete that never happened, leaving a stale rule live indefinitely.
                assert_wazuh_result_ok(resp, f"deleting orphaned rule {filename}")
                logger.info(f"Deleted orphaned rule: {filename}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during state reconciliation (Network/API): {e}")
        return False
    except ValueError as e:
        logger.error(f"Error parsing state reconciliation response: {e}")
        return False
    return True

def deploy_agent_conf(token: str, settings: Settings, tls_verify: Union[bool, str], dry_run: bool = False) -> bool:
    """Push agent.conf to the target group. Returns False on API failure."""
    logger.info(f"Deploying {settings.agent_conf_path} to Wazuh group: '{settings.target_group}'...")
    if not os.path.exists(settings.agent_conf_path):
        logger.warning(f"{settings.agent_conf_path} not found. Skipping agent.conf deployment.")
        return True

    if dry_run:
        logger.info("[DRY RUN] Would update agent.conf (Diffing agent.conf is unsupported via API).")
        return True

    with open(settings.agent_conf_path, 'r') as f:
        conf_content: str = f.read()

    url: str = f"{settings.wazuh_api_url}/groups/{settings.target_group}/configuration"

    headers: Dict[str, str] = {
        'Content-Type': 'application/xml',
        'Accept': 'application/json'
    }

    try:
        response, token = authed_request('PUT', url, settings, tls_verify, token, headers=headers, data=conf_content)
        assert_wazuh_result_ok(response, "deploying agent.conf")
        logger.info("Successfully deployed agent.conf")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error deploying agent.conf (Network/API): {e}")
        return False
    return True

def restart_manager(token: str, settings: Settings, tls_verify: Union[bool, str]) -> None:
    logger.info("Restarting Wazuh Manager to apply changes...")
    url: str = f"{settings.wazuh_api_url}/manager/restart"
    try:
        authed_request('PUT', url, settings, tls_verify, token)
        logger.info("Restart command issued successfully.")
    except requests.exceptions.RequestException as e:
        logger.error(f"CRITICAL: Network/HTTP error restarting manager: {e}")
        sys.exit(1)

def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy Wazuh Rules via API")
    parser.add_argument("--dry-run", action="store_true", help="Simulate deployment without making changes")
    args = parser.parse_args()

    if args.dry_run:
        logger.warning("=== DRY RUN MODE ACTIVATED - NO CHANGES WILL BE MADE ===")

    settings: Settings = load_settings()
    tls_verify: Union[bool, str] = get_tls_strategy(settings)

    token: str = get_token(settings, tls_verify, args.dry_run)

    success: bool = deploy_rules(token, settings, tls_verify, args.dry_run)
    if not success:
        logger.error("CRITICAL: One or more rules failed to deploy. Halting pipeline.")
        sys.exit(1)

    reconcile_ok: bool = reconcile_state(token, settings, tls_verify, args.dry_run)
    agent_conf_ok: bool = deploy_agent_conf(token, settings, tls_verify, args.dry_run)

    # The bundle was already PUT, so the manager must still restart to load it --
    # even if reconciliation or agent.conf failed. Restart first, then report the
    # partial failure with a non-zero exit so the pipeline never calls this a success.
    if args.dry_run:
        logger.info("Skipping SIEM Restart (Dry Run Complete).")
    else:
        restart_manager(token, settings, tls_verify)

    if not (reconcile_ok and agent_conf_ok):
        failed_steps = [
            name for name, ok in
            [("orphan reconciliation", reconcile_ok), ("agent.conf deployment", agent_conf_ok)]
            if not ok
        ]
        logger.error(f"CRITICAL: Deploy finished with failures: {', '.join(failed_steps)}.")
        sys.exit(1)

if __name__ == "__main__":
    main()
