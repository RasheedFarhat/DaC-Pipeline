import os
import sys
import yaml
import xml.etree.ElementTree as ET
from collections import Counter

SIGMA_DIR = "rules/sigma"
BUILD_DIR = "build/wazuh"

def validate_pipeline(directories):
    if isinstance(directories, str):
        directories = [directories]
        
    sigma_files = []
    xml_files = []

    for directory in directories:
        if not os.path.exists(directory):
            continue
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    sigma_files.append(os.path.join(root, file))
                elif file.endswith('.xml'):
                    xml_files.append(os.path.join(root, file))

    errors = []
    
    # 2. Parse Sigma & Collect Source of Truth UUIDs
    sigma_uuids = {} # map: UUID -> filepath
    for file in sigma_files:
        try:
            with open(file, 'r') as f:
                data = yaml.safe_load(f)
                if data and 'id' in data:
                    rule_id = data['id']
                    if rule_id in sigma_uuids:
                        errors.append(f"[!] Duplicate Sigma UUID: {rule_id} found in {file} and {sigma_uuids[rule_id]}")
                    else:
                        sigma_uuids[rule_id] = file
        except Exception as e:
            errors.append(f"[!] Error parsing YAML {file}: {e}")

    # 3. Parse XML, Validate Boundaries, & Enforce Correspondence
    xml_ids = []
    for file in xml_files:
        try:
            tree = ET.parse(file)
            for rule in tree.getroot().findall('.//rule'):
                rule_id = rule.get('id')
                
                # A. Integer & Range Validation
                if rule_id:
                    try:
                        rule_id_int = int(rule_id)
                        xml_ids.append((rule_id_int, file))
                        if rule_id_int < 100000:
                            errors.append(f"[!] Reserved ID Violation: Rule {rule_id_int} in {file}. Custom rules must be >= 100000.")
                    except ValueError:
                        errors.append(f"[!] Invalid ID Format: Rule '{rule_id}' in {file} is not an integer.")
                
                # B. Strict UUID Correspondence Validation
                sigma_ref = rule.find(".//info[@type='sigma_uuid']")
                if sigma_ref is None or not sigma_ref.text:
                    errors.append(f"[!] Orphaned XML (Omission): {file} (Rule {rule_id}) declares no Sigma parent (missing <info type='sigma_uuid'>).")
                elif sigma_ref.text not in sigma_uuids:
                    errors.append(f"[!] Dangling Reference: {file} (Rule {rule_id}) points to Sigma UUID '{sigma_ref.text}', which does not exist in the YAML source.")
                    
        except ET.ParseError as e:
            errors.append(f"[!] XML Parse Error in {file}: {e}")

    # 4. Check for duplicate Wazuh XML IDs
    id_counts = Counter([data[0] for data in xml_ids])
    duplicates = {id: count for id, count in id_counts.items() if count > 1}
    for dup_id in duplicates:
        shared_files = [file_path for rule_id, file_path in xml_ids if rule_id == dup_id]
        errors.append(f"[!] Duplicate Wazuh XML ID detected: {dup_id}\n    Shared by: {', '.join(shared_files)}")

    return errors

def main():
    print(f"[*] Starting Strict Validation & Correspondence Check in '{SIGMA_DIR}' and '{BUILD_DIR}'...\n")
    
    if not os.path.exists(SIGMA_DIR) and not os.path.exists(BUILD_DIR):
        print("[-] Rule directories not found. Exiting.")
        sys.exit(0)

    errors = validate_pipeline([SIGMA_DIR, BUILD_DIR])
    
    if errors:
        print("[-] CI/CD Pipeline halted. Validation failed with the following errors:\n")
        for error in errors:
            print(error)
        sys.exit(1)
    else:
        print("[+] PASSED: All rules are valid, unique, and strictly linked via UUID.")
        sys.exit(0)

if __name__ == "__main__":
    main()
