import os
import sys
import xml.etree.ElementTree as ET
import yaml
import logging

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
# -----------------------------

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
    sigma_uuids = set()
    wazuh_ids = {}

    for filepath in sigma_files:
        with open(filepath, 'r') as f:
            try:
                data = yaml.safe_load(f)
                uuid = data.get('id')
                if uuid:
                    if uuid in sigma_uuids:
                        errors.append(f"[!] Duplicate Sigma UUID detected: {uuid} in {filepath}")
                    sigma_uuids.add(uuid)
            except yaml.YAMLError as e:
                errors.append(f"[!] Invalid YAML in {filepath}: {e}")

    for filepath in xml_files:
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            for rule in root.findall('.//rule'):
                rule_id = rule.get('id')
                info_tag = rule.find(".//info[@type='sigma_uuid']")
                
                if rule_id:
                    if rule_id in wazuh_ids:
                        wazuh_ids[rule_id].append(filepath)
                    else:
                        wazuh_ids[rule_id] = [filepath]

                if info_tag is not None and info_tag.text:
                    if info_tag.text not in sigma_uuids:
                        errors.append(f"[!] Orphaned XML (Dangling): {filepath} references Sigma UUID {info_tag.text}, but it does not exist in the repository.")
                else:
                    errors.append(f"[!] Orphaned XML (Omission): {filepath} (Rule {rule_id}) declares no Sigma parent (missing <info type='sigma_uuid'>).")
        except ET.ParseError as e:
            errors.append(f"[!] Invalid XML in {filepath}: {e}")

    for rule_id, files in wazuh_ids.items():
        if len(files) > 1:
            files_str = ', '.join(files)
            errors.append(f"[!] Duplicate Wazuh XML ID detected: {rule_id}\n    Shared by: {files_str}")

    return errors

def main():
    logger.info(f"Starting Strict Validation & Correspondence Check in '{SIGMA_DIR}' and '{BUILD_DIR}'...")
    
    if not os.path.exists(SIGMA_DIR) and not os.path.exists(BUILD_DIR):
        logger.error("Rule directories not found. Exiting.")
        sys.exit(0)

    errors = validate_pipeline([SIGMA_DIR, BUILD_DIR])
    
    if errors:
        logger.error("CI/CD Pipeline halted. Validation failed with the following errors:")
        for error in errors:
            logger.error(error)
        sys.exit(1)
    else:
        logger.info("PASSED: All rules are valid, unique, and strictly linked via UUID.")
        sys.exit(0)

if __name__ == "__main__":
    main()
