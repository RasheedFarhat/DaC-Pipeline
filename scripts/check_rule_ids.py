import os
import re
import sys
import xml.etree.ElementTree as ET
import yaml
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

def load_config() -> dict:
    """Read directory paths from pipeline.yaml, matching compile_sigma.py, so the
    validator checks the same directories the compiler wrote to."""
    try:
        with open("pipeline.yaml", "r") as f:
            config = yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("pipeline.yaml not found, falling back to defaults.")
        config = {}
    build = config.get("build", {})
    return {
        "sigma_dir": build.get("sigma_dir", "rules/sigma"),
        "wazuh_dir": build.get("wazuh_dir", "build/wazuh"),
    }

CONFIG = load_config()
SIGMA_DIR = CONFIG["sigma_dir"]
BUILD_DIR = CONFIG["wazuh_dir"]

def build_has_xml(directory: str) -> bool:
    """Recursively checks if at least one XML file exists in the directory."""
    for _, _, files in os.walk(directory):
        if any(f.endswith('.xml') for f in files):
            return True
    return False

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

    if sigma_files and not xml_files:
        errors.append("[!] CRITICAL: Sigma YAML files exist, but no Wazuh XML files were found to validate.")

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

            # UUID is stored as an XML comment (<!-- sigma_uuid:UUID -->), which
            # ElementTree drops, so read the raw text -- once per file, not once
            # per <rule>. The comment is file-scoped: the compiler writes exactly
            # one rule per file, so every rule in the file shares it.
            with open(filepath, 'r') as f:
                raw = f.read()
            comment_match = re.search(r'<!--\s*sigma_uuid:([\w-]+)\s*-->', raw)
            uuid_from_comment = comment_match.group(1) if comment_match else None

            for rule in root.findall('.//rule'):
                rule_id = rule.get('id')

                if rule_id:
                    try:
                        rule_id_int = int(rule_id)
                        if rule_id_int < 200000:
                            errors.append(f"[!] Reserved ID Violation: Rule {rule_id_int} in {filepath}. Custom rules must be >= 200000.")
                    except ValueError:
                        errors.append(f"[!] Invalid ID Format: Rule '{rule_id}' in {filepath} is not an integer.")

                    if rule_id in wazuh_ids:
                        wazuh_ids[rule_id].append(filepath)
                    else:
                        wazuh_ids[rule_id] = [filepath]

                if uuid_from_comment:
                    if uuid_from_comment not in sigma_uuids:
                        errors.append(f"[!] Orphaned XML (Dangling): {filepath} references Sigma UUID {uuid_from_comment}, but it does not exist in the repository.")
                else:
                    errors.append(f"[!] Orphaned XML (Omission): {filepath} (Rule {rule_id}) declares no Sigma parent (missing sigma_uuid comment).")
        except ET.ParseError as e:
            errors.append(f"[!] Invalid XML in {filepath}: {e}")

    for rule_id, files in wazuh_ids.items():
        if len(files) > 1:
            files_str = ', '.join(files)
            errors.append(f"[!] Duplicate Wazuh XML ID detected: {rule_id}\n    Shared by: {files_str}")

    return errors

def main():
    logger.info(f"Starting Strict Validation & Correspondence Check...")

    if not os.path.exists(SIGMA_DIR):
        logger.error("CRITICAL: Sigma rule directory missing.")
        sys.exit(1)

    # Use recursive check so subdirectories aren't falsely flagged as empty
    if not os.path.exists(BUILD_DIR) or not build_has_xml(BUILD_DIR):
        logger.error("CRITICAL: Build directory empty or missing. Did compile_sigma.py run?")
        sys.exit(1)

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
