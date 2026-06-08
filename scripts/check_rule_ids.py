import os
import sys
import yaml
from collections import Counter

# Define the path to your Sigma rules directory
RULES_DIR = "rules"

def get_yaml_files(directory):
    """Recursively find all .yml files in the given directory."""
    yaml_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.yml') or file.endswith('.yaml'):
                yaml_files.append(os.path.join(root, file))
    return yaml_files

def extract_rule_ids(files):
    """Parse YAML files and extract the 'id' field."""
    rule_ids = []
    for file in files:
        try:
            with open(file, 'r') as f:
                # Safe load to prevent arbitrary code execution
                rule_data = yaml.safe_load(f)
                if rule_data and 'id' in rule_data:
                    rule_ids.append((rule_data['id'], file))
        except Exception as e:
            print(f"Error parsing {file}: {e}")
    return rule_ids

def main():
    print(f"Scanning directory: {RULES_DIR} for Sigma rules...")
    files = get_yaml_files(RULES_DIR)
    
    if not files:
        print("No rule files found. Pipeline passes.")
        sys.exit(0)

    extracted_data = extract_rule_ids(files)
    
    # Isolate just the IDs for counting
    just_ids = [data[0] for data in extracted_data]
    id_counts = Counter(just_ids)
    
    # Filter for IDs that appear more than once
    duplicates = {id: count for id, count in id_counts.items() if count > 1}

    if duplicates:
        print("\n[FAILED] CI/CD Pipeline halted. Duplicate Rule IDs detected:")
        for dup_id in duplicates:
            print(f"\nID: {dup_id} is shared by:")
            for rule_id, file_path in extracted_data:
                if rule_id == dup_id:
                    print(f"  - {file_path}")
        # Exit with error code 1 to fail the GitHub Action
        sys.exit(1)
    else:
        print(f"\n[PASSED] {len(extracted_data)} rules scanned. No duplicate IDs found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
