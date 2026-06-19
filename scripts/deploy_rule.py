import os
import sys
import requests
import logging
import argparse
import yaml
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception, before_sleep_log

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- Load Pipeline Configuration ---
try:
    with open("pipeline.yaml", "r") as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    logger.warning("pipeline.yaml not found. Using default configurations.")
    config = {}

RULES_DIR = config.get("build", {}).get("wazuh_dir", "build/wazuh")
AGENT_CONF_PATH = config.get("deploy", {}).get("agent_conf_path", "configs/agent.conf")
TARGET_GROUP = config.get("deploy", {}).get("target_group", "default")
YAML_API_URL = config.get("deploy", {}).get("api_url", "https://localhost:55000")

# --- Environment Variables (Overrides YAML) ---
WAZUH_API_URL = os.environ.get("WAZUH_API_URL", YAML_API_URL)
WAZUH_USER = os.environ.get("WAZUH_USER")
WAZUH_PASSWORD = os.environ.get("WAZUH_PASSWORD")

# --- Security Configuration ---
CA_BUNDLE_PATH = os.environ.get("WAZUH_CA_BUNDLE")
INSECURE_MODE = os.environ.get("WAZUH_INSECURE", "false").lower() == "true"

if CA_BUNDLE_PATH and os.path.exists(CA_BUNDLE_PATH):
    TLS_VERIFY = CA_BUNDLE_PATH
elif INSECURE_MODE:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    TLS_VERIFY = False
    logger.warning("INSECURE MODE ACTIVATED: TLS certificate verification is disabled.")
else:
    TLS_VERIFY = True 

def is_retryable_exception(exception):
    if isinstance(exception, requests.exceptions.HTTPError):
        status = exception.response.status_code
        return status == 429 or status >= 500
    return isinstance(exception, (requests.exceptions.ConnectionError, requests.exceptions.Timeout))

@retry(
    retry=retry_if_exception(is_retryable_exception),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    stop=stop_after_attempt(5),
    before_sleep=before_sleep_log(logger, logging.WARNING)
)
def safe_api_request(method, url, **kwargs):
    response = requests.request(method, url, **kwargs)
    response.raise_for_status() 
    return response

def get_token():
    logger.info("Authenticating to the Wazuh API...")
    if not WAZUH_USER or not WAZUH_PASSWORD:
        logger.error("CRITICAL: WAZUH_USER and WAZUH_PASSWORD environment variables must be set.")
        sys.exit(1) # CRITICAL FIX: Hard stop on missing credentials
        
    url = f"{WAZUH_API_URL}/security/user/authenticate"
    try:
        response = safe_api_request('GET', url, auth=(WAZUH_USER, WAZUH_PASSWORD), verify=TLS_VERIFY)
        logger.info("Authentication successful.")
        return response.json()['data']['token']
    except Exception as e:
        logger.error(f"CRITICAL: Authentication failed: {e}")
        sys.exit(1) # CRITICAL FIX: Hard stop on auth failure

def deploy_rules(token, dry_run=False):
    logger.info(f"Scanning {RULES_DIR} for rule files...")
    if not os.path.exists(RULES_DIR):
        logger.error(f"CRITICAL: Directory {RULES_DIR} not found. Did the compiler run?")
        sys.exit(1) # CRITICAL FIX: Hard stop if build directory is missing

    headers = {'Authorization': f'Bearer {token}'}
    success = True

    for filename in os.listdir(RULES_DIR):
        if not filename.endswith(".xml"):
            continue

        filepath = os.path.join(RULES_DIR, filename)
        with open(filepath, 'r') as f:
            xml_content = f.read()

        if dry_run:
            logger.info(f"[DRY RUN] Would create/update file: {filename}")
            continue

        url = f"{WAZUH_API_URL}/rules/files/{filename}"
        try:
            safe_api_request('PUT', url, headers=headers, data=xml_content, verify=TLS_VERIFY)
            logger.info(f"Successfully deployed {filename}")
        except Exception as e:
            logger.error(f"ERROR: Failed deploying {filename}: {e}")
            success = False

    return success

def reconcile_state(token, dry_run=False):
    # (Keeping state reconciliation logic identical to your previous version)
    logger.info("Reconciling State (Detecting and deleting orphaned rules)...")
    IGNORE_FILES = {"local_rules.xml"}
    try:
        response = safe_api_request('GET', f"{WAZUH_API_URL}/rules/files", headers={'Authorization': f'Bearer {token}'}, verify=TLS_VERIFY)
        resp_json = response.json()
        
        remote_custom_files = set()
        items = resp_json.get('data', {}).get('affected_items', [])
        if not items:
            items = resp_json.get('data', {}).get('items', [])
            
        for item in items:
            path = item.get('path', '')
            filename = item.get('filename') or item.get('file')
            if filename and filename.endswith('.xml') and 'etc/rules' in path:
                remote_custom_files.add(filename)
                
        local_files = {f for f in os.listdir(RULES_DIR) if f.endswith(".xml")} if os.path.exists(RULES_DIR) else set()
        orphaned_files = (remote_custom_files - local_files) - IGNORE_FILES
        
        if not orphaned_files:
            logger.info("State matches. No orphaned rules to delete.")
            return

        for filename in orphaned_files:
            if dry_run:
                logger.info(f"[DRY RUN] Would DELETE orphaned rule: {filename}")
            else:
                safe_api_request('DELETE', f"{WAZUH_API_URL}/rules/files/{filename}", headers={'Authorization': f'Bearer {token}'}, verify=TLS_VERIFY)
                logger.info(f"Deleted orphaned rule: {filename}")
    except Exception as e:
        logger.error(f"Error during state reconciliation: {e}")

def deploy_agent_conf(token, dry_run=False):
    logger.info(f"Deploying {AGENT_CONF_PATH} to Wazuh group: '{TARGET_GROUP}'...")
    if not os.path.exists(AGENT_CONF_PATH):
        logger.warning(f"{AGENT_CONF_PATH} not found. Skipping agent.conf deployment.")
        return

    if dry_run:
        logger.info("[DRY RUN] Would update agent.conf (Diffing agent.conf is unsupported via API).")
        return

    with open(AGENT_CONF_PATH, 'r') as f:
        conf_content = f.read()

    url = f"{WAZUH_API_URL}/groups/{TARGET_GROUP}/configuration"
    headers = {'Authorization': f'Bearer {token}'}
    try:
        safe_api_request('PUT', url, headers=headers, data=conf_content, verify=TLS_VERIFY)
        logger.info("Successfully deployed agent.conf")
    except Exception as e:
        logger.error(f"Error deploying agent.conf: {e}")
        # Not a hard exit here to allow rule deployment to finish, but could be adjusted

def restart_manager(token):
    logger.info("Restarting Wazuh Manager to apply changes...")
    url = f"{WAZUH_API_URL}/manager/restart"
    headers = {'Authorization': f'Bearer {token}'}
    try:
        safe_api_request('PUT', url, headers=headers, verify=TLS_VERIFY)
        logger.info("Restart command issued successfully.")
    except Exception as e:
        logger.error(f"Error restarting manager: {e}")
        sys.exit(1) # CRITICAL FIX: Fail the pipeline if the SIEM doesn't restart

def main():
    parser = argparse.ArgumentParser(description="Deploy Wazuh Rules via API")
    parser.add_argument("--dry-run", action="store_true", help="Simulate deployment without making changes")
    args = parser.parse_args()

    if args.dry_run:
        logger.warning("=== DRY RUN MODE ACTIVATED - NO CHANGES WILL BE MADE ===")

    token = get_token()
    
    success = deploy_rules(token, args.dry_run)
    if not success:
        logger.error("CRITICAL: One or more rules failed to deploy. Halting pipeline.")
        sys.exit(1) # CRITICAL FIX: Hard stop if partial failure occurs

    reconcile_state(token, args.dry_run)
    deploy_agent_conf(token, args.dry_run)

    if args.dry_run:
        logger.info("Skipping SIEM Restart (Dry Run Complete).")
    else:
        restart_manager(token)

if __name__ == "__main__":
    main()
