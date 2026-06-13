import os
import sys
import yaml
import xml.etree.ElementTree as ET
from collections import Counter

RULES_DIR = "rules"

def check_sigma_yaml(directory):
    """Parses YAML files and checks for duplicate Sigma UUIDs."""
    yaml_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.yml') or file.endswith('.yaml'):
                yaml_files.append(os.path.join(root, file))

    rule_ids = []
    errors = []
    
    for file in yaml_files:
        try:
            with open(file, 'r') as f:
                rule_data = yaml.safe_load(f)
                if rule_data and 'id' in rule_data:
                    rule_ids.append((rule_data['id'], file))
        except Exception as e:
            errors.append(f"[!] Error parsing YAML {file}: {e}")

    return check_duplicates(rule_ids, "Sigma UUID", errors)

def check_wazuh_xml(directory):
    """Parses XML files, checks for duplicate Wazuh IDs, and enforces range limits."""
    xml_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.xml'):
                xml_files.append(os.path.join(root, file))

    rule_ids = []
    errors = []

    for file in xml_files:
        try:
            tree = ET.parse(file)
            xml_root = tree.getroot()
            
            # Find every <rule> tag in the XML file
            for rule in xml_root.findall('.//rule'):
                rule_id = rule.get('id')
                if rule_id:
                    try:
                        rule_id_int = int(rule_id)
                        rule_ids.append((rule_id_int, file))
                        
                        # Wazuh Custom Rule Boundary Check
                        if rule_id_int < 100000:
                            errors.append(f"[!] Reserved ID Violation: ID {rule_id_int} in {file}. Custom rules must be >= 100000.")
                    except ValueError:
                        errors.append(f"[!] Invalid ID Format: '{rule_id}' in {file} is not an integer.")
        except ET.ParseError as e:
            errors.append(f"[!] XML Parse Error in {file}: {e}")

    return check_duplicates(rule_ids, "Wazuh XML ID", errors)

def check_duplicates(extracted_data, id_type, errors):
    """Helper function to count IDs and append duplicate errors."""
    just_ids = [data[0] for data in extracted_data]
    id_counts = Counter(just_ids)
    
    duplicates = {id: count for id, count in id_counts.items() if count > 1}
    
    for dup_id in duplicates:
        # Find all files that share this duplicate ID
        shared_files = [file_path for rule_id, file_path in extracted_data if rule_id == dup_id]
        errors.append(f"[!] Duplicate {id_type} detected: {dup_id}\n    Shared by: {', '.join(shared_files)}")
        
    return errors

def main():
    print(f"[*] Scanning directory: {RULES_DIR} for rule conflicts...\n")
    
    if not os.path.exists(RULES_DIR):
        print(f"[-] Directory '{RULES_DIR}' not found. Exiting.")
        sys.exit(0)

    # Run both checks
    yaml_errors = check_sigma_yaml(RULES_DIR)
    xml_errors = check_wazuh_xml(RULES_DIR)
    
    all_errors = yaml_errors + xml_errors

    if all_errors:
        print("[-] CI/CD Pipeline halted. Rule validation failed with the following errors:\n")
        for error in all_errors:
            print(error)
        sys.exit(1)
    else:
        print("[+] PASSED: All Sigma UUIDs and Wazuh XML IDs are unique and valid.")
        sys.exit(0)

if __name__ == "__main__":
    main()