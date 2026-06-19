import os
import sys
import requests
import logging
import argparse
import yaml
from typing import Any, Dict, Set, Optional, Union, List
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception, before_sleep_log

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- Load Pipeline Configuration ---
config: Dict[str, Any] = {}
try:
    with open("pipeline.yaml", "r") as f:
        loaded_config = yaml.safe_load(f)
        if loaded_config:
            config = loaded_config
except FileNotFoundError:
    logger.warning("pipeline.yaml not found. Using default configurations.")

RULES_DIR: str = config.get("build", {}).get("wazuh_dir", "build/wazuh")
AGENT_CONF_PATH: str = config.get("deploy", {}).get("agent_conf_path", "configs/agent.conf")
TARGET_GROUP: str = config.get("deploy", {}).get("target_group", "default")
YAML_API_URL: str = config.get("deploy", {}).get("api_url", "https://localhost:55000")

# --- Environment Variables (Overrides YAML) ---
WAZUH_API_URL: str = os.environ.get("WAZUH_API_URL", YAML_API_URL)
WAZUH_USER: Optional[str] = os.environ.get("WAZUH_USER")
WAZUH_PASSWORD: Optional[str] = os.environ.get("WAZUH_PASSWORD")

# --- Security Configuration ---
CA_BUNDLE_PATH: Optional[str] = os.environ.get("WAZUH_CA_BUNDLE")
INSECURE_MODE: bool = os.environ.get("WAZUH_INSECURE", "false").lower() == "true"

TLS_VERIFY: Union[bool, str]
if CA_BUNDLE_PATH and os.path.exists(CA_BUNDLE_PATH):
    TLS_VERIFY = CA_BUNDLE_PATH
elif INSECURE_MODE:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    TLS_VERIFY = False
    logger.warning("INSECURE MODE ACTIVATED: TLS certificate verification is disabled.")
else:
    TLS_VERIFY = True

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

def get_token() -> str:
    logger.info("Authenticating to the Wazuh API...")
    if not WAZUH_USER or not WAZUH_PASSWORD:
        logger.error("CRITICAL: WAZUH_USER and WAZUH_PASSWORD environment variables must be set.")
        sys.exit(1)

    url: str = f"{WAZUH_API_URL}/security/user/authenticate"
    try:
        response: requests.Response = safe_api_request('GET', url, auth=(WAZUH_USER, WAZUH_PASSWORD), verify=TLS_VERIFY)
        logger.info("Authentication successful.")
        return str(response.json()['data']['token'])
    except requests.exceptions.RequestException as e:
        logger.error(f"CRITICAL: Network or HTTP error during authentication: {e}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"CRITICAL: Failed to parse JSON response during authentication: {e}")
        sys.exit(1)

def deploy_rules(token: str, dry_run: bool = False) -> bool:
    logger.info(f"Scanning {RULES_DIR} for rule files...")
    if not os.path.exists(RULES_DIR):
        logger.error(f"CRITICAL: Directory {RULES_DIR} not found. Did the compiler run?")
        sys.exit(1)

    headers: Dict[str, str] = {'Authorization': f'Bearer {token}'}
    success: bool = True

    for filename in os.listdir(RULES_DIR):
        if not filename.endswith(".xml"):
            continue

        filepath: str = os.path.join(RULES_DIR, filename)
        with open(filepath, 'r') as f:
            xml_content: str = f.read()

        if dry_run:
            logger.info(f"[DRY RUN] Would create/update file: {filename}")
            continue

        url: str = f"{WAZUH_API_URL}/rules/files/{filename}"
        try:
            safe_api_request('PUT', url, headers=headers, data=xml_content, verify=TLS_VERIFY)
            logger.info(f"Successfully deployed {filename}")
        except requests.exceptions.RequestException as e:
            logger.error(f"ERROR: Network or API failure deploying {filename}: {e}")
            success = False

    return success

def reconcile_state(token: str, dry_run: bool = False) -> None:
    logger.info("Reconciling State (Detecting and deleting orphaned rules)...")
    IGNORE_FILES: Set[str] = {"local_rules.xml"}
    try:
        response: requests.Response = safe_api_request('GET', f"{WAZUH_API_URL}/rules/files", headers={'Authorization': f'Bearer {token}'}, verify=TLS_VERIFY)
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

        local_files: Set[str] = {f for f in os.listdir(RULES_DIR) if f.endswith(".xml")} if os.path.exists(RULES_DIR) else set()
        orphaned_files: Set[str] = (remote_custom_files - local_files) - IGNORE_FILES

        if not orphaned_files:
            logger.info("State matches. No orphaned rules to delete.")
            return

        for filename in orphaned_files:
            if dry_run:
                logger.info(f"[DRY RUN] Would DELETE orphaned rule: {filename}")
            else:
                safe_api_request('DELETE', f"{WAZUH_API_URL}/rules/files/{filename}", headers={'Authorization': f'Bearer {token}'}, verify=TLS_VERIFY)
                logger.info(f"Deleted orphaned rule: {filename}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error during state reconciliation (Network/API): {e}")
    except ValueError as e:
        logger.error(f"Error parsing state reconciliation response: {e}")

def deploy_agent_conf(token: str, dry_run: bool = False) -> None:
    logger.info(f"Deploying {AGENT_CONF_PATH} to Wazuh group: '{TARGET_GROUP}'...")
    if not os.path.exists(AGENT_CONF_PATH):
        logger.warning(f"{AGENT_CONF_PATH} not found. Skipping agent.conf deployment.")
        return

    if dry_run:
        logger.info("[DRY RUN] Would update agent.conf (Diffing agent.conf is unsupported via API).")
        return

    with open(AGENT_CONF_PATH, 'r') as f:
        conf_content: str = f.read()

    url: str = f"{WAZUH_API_URL}/groups/{TARGET_GROUP}/configuration"
    headers: Dict[str, str] = {'Authorization': f'Bearer {token}'}
    try:
        safe_api_request('PUT', url, headers=headers, data=conf_content, verify=TLS_VERIFY)
        logger.info("Successfully deployed agent.conf")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error deploying agent.conf (Network/API): {e}")

def restart_manager(token: str) -> None:
    logger.info("Restarting Wazuh Manager to apply changes...")
    url: str = f"{WAZUH_API_URL}/manager/restart"
    headers: Dict[str, str] = {'Authorization': f'Bearer {token}'}
    try:
        safe_api_request('PUT', url, headers=headers, verify=TLS_VERIFY)
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

    token: str = get_token()

    success: bool = deploy_rules(token, args.dry_run)
    if not success:
        logger.error("CRITICAL: One or more rules failed to deploy. Halting pipeline.")
        sys.exit(1)

    reconcile_state(token, args.dry_run)
    deploy_agent_conf(token, args.dry_run)

    if args.dry_run:
        logger.info("Skipping SIEM Restart (Dry Run Complete).")
    else:
        restart_manager(token)

if __name__ == "__main__":
    main()
