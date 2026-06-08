import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# API connection details
API_URL = "https://127.0.0.1:55000"
USER = "wazuh-wui"
PASSWORD = "MyS3cr37P450r.*-"
RULES_DIR = "rules/wazuh" # We will create this subfolder next

def main():
    print("[*] 1. Authenticating to the Wazuh API...")
    try:
        auth_response = requests.post(f"{API_URL}/security/user/authenticate", auth=(USER, PASSWORD), verify=False)
        auth_response.raise_for_status()
        token = auth_response.json()['data']['token']
        print("[+] Authentication successful.")
    except Exception as e:
        print(f"[-] Authentication failed: {e}")
        return

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/octet-stream'
    }

    print(f"[*] 2. Scanning {RULES_DIR} for rule files...")
    if not os.path.exists(RULES_DIR):
        print(f"[-] Directory {RULES_DIR} not found.")
        return

    # Loop through all XML files in the directory
    for filename in os.listdir(RULES_DIR):
        if filename.endswith(".xml"):
            file_path = os.path.join(RULES_DIR, filename)
            print(f"  -> Deploying {filename}...")
            
            with open(file_path, 'r') as file:
                rule_data = file.read()
                
            upload_response = requests.put(
                f"{API_URL}/rules/files/{filename}",
                headers=headers,
                data=rule_data.strip(),
                params={'overwrite': 'true'},
                verify=False
            )
            
            if upload_response.status_code == 200:
                print(f"     [+] Success: {filename}")
            else:
                print(f"     [-] Failed: {upload_response.text}")

    print("[*] 3. Restarting the SIEM Analysis Engine...")
    restart_response = requests.put(
        f"{API_URL}/manager/restart",
        headers={'Authorization': f'Bearer {token}'},
        verify=False
    )
    
    if restart_response.status_code == 200:
        print("[+] Restart initiated. All rules are now live!")
    else:
        print(f"[-] Restart failed: {restart_response.text}")

if __name__ == "__main__":
    main()
