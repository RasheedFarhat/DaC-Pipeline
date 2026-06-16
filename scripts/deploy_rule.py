import os
import sys
import time
import argparse
import difflib
import requests
import urllib3

# Setup argparse
parser = argparse.ArgumentParser(description="Deploy detection rules to Wazuh.")
parser.add_argument('--dry-run', action='store_true', help="Preview changes without modifying the SIEM.")
args = parser.parse_args()

# Environment variables
API_URL = os.environ.get("WAZUH_API_URL", "https://127.0.0.1:55000")
USER = os.environ.get("WAZUH_USER")
PASSWORD = os.environ.get("WAZUH_PASSWORD")
RULES_DIR = "build/wazuh"
CONFIG_FILE = "configs/agent.conf"
TARGET_GROUP = "default"

# TLS Configuration
VERIFY_ENV = os.environ.get("WAZUH_VERIFY_TLS", "True").lower()
CA_BUNDLE = os.environ.get("WAZUH_CA_BUNDLE")

if CA_BUNDLE and os.path.exists(CA_BUNDLE):
    TLS_VERIFY = CA_BUNDLE
elif VERIFY_ENV in ['false', '0', 'no']:
    TLS_VERIFY = False
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
else:
    TLS_VERIFY = True

def print_diff(remote_text, local_text, filename):
    """Generates and prints a unified diff between remote and local files."""
    diff = list(difflib.unified_diff(
        remote_text.splitlines(),
        local_text.splitlines(),
        fromfile=f"remote/{filename}",
        tofile=f"local/{filename}",
        lineterm=''
    ))
    
    if not diff:
        print("     [=] No changes detected.")
        return
        
    for line in diff:
        if line.startswith('+') and not line.startswith('+++'):
            print(f"     + {line}")
        elif line.startswith('-') and not line.startswith('---'):
            print(f"     - {line}")
        elif line.startswith('@@'):
            print(f"     {line}")

def reconcile_state(api_url, token, local_dir, dry_run=False):
    """Fetches custom rules from Wazuh and deletes any that are not in the local Git repository."""
    print("\n[*] 3. Reconciling State (Detecting and deleting orphaned rules)...")
    
    # Wazuh ships with this custom file by default. Ignoring it prevents accidental 
    # deletion of pre-existing manual rules.
    IGNORE_FILES = {"local_rules.xml"}
    
    try:
        # Removed the query parameter. We fetch all files and filter locally.
        response = requests.get(
            f"{api_url}/rules/files",
            headers={'Authorization': f'Bearer {token}'},
            verify=TLS_VERIFY
        )
        response.raise_for_status()
        resp_json = response.json()
        
        remote_custom_files = set()
        
        # Handle both legacy and current Wazuh API response structures
        items = resp_json.get('data', {}).get('affected_items', [])
        if not items:
            items = resp_json.get('data', {}).get('items', [])
            
        for item in items:
            path = item.get('path', '')
            filename = item.get('filename') or item.get('file')
            
            # Custom rules are physically stored in the 'etc/rules' directory 
            if filename and filename.endswith('.xml') and 'etc/rules' in path:
                remote_custom_files.add(filename)
                
        local_files = {f for f in os.listdir(local_dir) if f.endswith(".xml")}
        orphaned_files = (remote_custom_files - local_files) - IGNORE_FILES
        
        if not orphaned_files:
            print("     [+] State matches. No orphaned rules to delete.")
            return

        for filename in orphaned_files:
            if dry_run:
                print(f"     [DRY RUN] Would DELETE orphaned rule: {filename}")
            else:
                delete_resp = requests.delete(
                    f"{api_url}/rules/files/{filename}",
                    headers={'Authorization': f'Bearer {token}'},
                    verify=TLS_VERIFY
                )
                if delete_resp.status_code == 200:
                    print(f"     [+] Deleted orphaned rule: {filename}")
                else:
                    print(f"     [-] Failed to delete {filename}: {delete_resp.text}")
                    
    except Exception as e:
        print(f"     [-] Error during state reconciliation: {e}")

def push_agent_config(api_url, token, group_name, conf_path, dry_run=False):
    if not os.path.exists(conf_path):
        print(f"[-] Directory/File {conf_path} not found. Skipping config deployment.")
        return

    print(f"\n[*] 4. Deploying {conf_path} to Wazuh group: '{group_name}'...")
    if dry_run:
        print("     [DRY RUN] Would update agent.conf (Diffing agent.conf is unsupported via API).")
        return

    endpoint = f"{api_url}/groups/{group_name}/configuration"
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/xml',
        'Accept': 'application/json'
    }
    
    try:
        with open(conf_path, 'r') as file:
            xml_payload = file.read()
            
        response = requests.put(endpoint, headers=headers, data=xml_payload, verify=TLS_VERIFY)
        
        if response.status_code == 200:
            print("     [+] Successfully updated agent.conf!")
        else:
            print(f"     [-] Failed to update agent.conf. Status Code: {response.status_code}")
            
    except Exception as e:
        print(f"     [-] An unexpected error occurred pushing config: {e}")

def check_health(api_url, token, timeout=60):
    print("\n[*] 5. Polling for Wazuh Analysisd Health...")
    headers = {'Authorization': f'Bearer {token}'}
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"{api_url}/manager/status", headers=headers, verify=TLS_VERIFY)
            if response.status_code == 200:
                status_data = response.json().get('data', {})
                if status_data.get('wazuh-analysisd') == 'running':
                    print("     [+] wazuh-analysisd is RUNNING. Restart complete and healthy!")
                    return True
        except Exception:
            pass
        
        print("     [-] Waiting for manager to come online...")
        time.sleep(5)
        
    print(f"     [!] FATAL: Manager failed to report healthy within {timeout} seconds.")
    return False

def main():
    if not USER or not PASSWORD:
        print("[-] FATAL: WAZUH_USER and WAZUH_PASSWORD environment variables must be set.")
        sys.exit(1)

    print("[*] 1. Authenticating to the Wazuh API...")
    try:
        auth_response = requests.post(f"{API_URL}/security/user/authenticate", auth=(USER, PASSWORD), verify=TLS_VERIFY)
        auth_response.raise_for_status()
        token = auth_response.json()['data']['token']
        print("[+] Authentication successful.")
    except Exception as e:
        print(f"[-] Authentication failed: {e}")
        sys.exit(1)

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/octet-stream'
    }

    if args.dry_run:
        print("\n[!] === DRY RUN MODE ACTIVATED - NO CHANGES WILL BE MADE === [!]")

    print(f"\n[*] 2. Scanning {RULES_DIR} for rule files...")
    if os.path.exists(RULES_DIR):
        for filename in os.listdir(RULES_DIR):
            if filename.endswith(".xml"):
                file_path = os.path.join(RULES_DIR, filename)
                print(f"  -> Processing {filename}...")
                
                with open(file_path, 'r') as file:
                    rule_data = file.read().strip()
                
                if args.dry_run:
                    get_resp = requests.get(f"{API_URL}/rules/files/{filename}", headers={'Authorization': f'Bearer {token}'}, verify=TLS_VERIFY)
                    remote_content = ""
                    
                    if get_resp.status_code == 200:
                        try:
                            get_json = get_resp.json()
                            if 'data' in get_json and isinstance(get_json['data'], list) and len(get_json['data']) > 0:
                                remote_content = get_json['data'][0].get('contents', '')
                            elif 'data' in get_json and isinstance(get_json['data'], dict):
                                remote_content = get_json['data'].get('contents', '')
                        except:
                            remote_content = ""
                    
                    if not remote_content:
                        print(f"     [+] NEW FILE: {filename} will be created.")
                    else:
                        print_diff(remote_content, rule_data, filename)
                    continue

                upload_response = requests.put(
                    f"{API_URL}/rules/files/{filename}",
                    headers=headers,
                    data=rule_data,
                    params={'overwrite': 'true'},
                    verify=TLS_VERIFY
                )
                
                if upload_response.status_code == 200:
                    print(f"     [+] Success: {filename}")
                else:
                    print(f"     [-] Failed: {upload_response.text}")

    reconcile_state(API_URL, token, RULES_DIR, dry_run=args.dry_run)
    push_agent_config(API_URL, token, TARGET_GROUP, CONFIG_FILE, dry_run=args.dry_run)

    if args.dry_run:
        print("\n[*] 6. Skipping SIEM Restart (Dry Run Complete).")
        sys.exit(0)

    print("\n[*] 6. Restarting the SIEM Analysis Engine...")
    restart_response = requests.put(
        f"{API_URL}/manager/restart",
        headers={'Authorization': f'Bearer {token}'},
        verify=TLS_VERIFY
    )
    
    if restart_response.status_code == 200:
        print("[+] Restart command accepted.")
        if not check_health(API_URL, token):
            sys.exit(1)
    else:
        print(f"[-] Restart failed: {restart_response.text}")
        sys.exit(1)

if __name__ == "__main__":
    main()
