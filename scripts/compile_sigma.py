import os
import re
import sys
import shutil
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, List
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

SIGMA_DIR: str = "rules/sigma"
BUILD_DIR: str = "build/wazuh"
TEMPLATE_DIR: str = "templates"

env: Environment = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(['xml', 'j2'])
)
template = env.get_template('wazuh_rule.xml.j2')

def map_wazuh_level(sigma_level: str) -> int:
    mapping: Dict[str, int] = {'informational': 3, 'low': 5, 'medium': 7, 'high': 10, 'critical': 12}
    return mapping.get(sigma_level.lower(), 5)

def get_parent_group(service: str, category: str = '', product: str = '') -> str:
    service_lower = service.lower() if service else ''
    category_lower = category.lower() if category else ''

    if service_lower == 'sysmon' or category_lower == 'process_creation':
        return 'sysmon_event1'
    if service_lower == 'syscheck':
        return 'syscheck'
    return 'syslog'

def process_modifiers(values: List[Any], modifiers: List[str]) -> str:
    raw_vals = []
    for v in values:
        if hasattr(v, 'to_plain'):
            raw_vals.append(v.to_plain())
        else:
            raw_vals.append(str(v))

    # Strip wildcards pySigma pre-embeds via contains modifier before escaping
    if 'all' in modifiers:
        stripped_vals = [v.strip('*') for v in raw_vals]
        escaped_vals = [re.escape(v) for v in stripped_vals]
        if 'endswith' in modifiers:
            return "".join([f"(?=.*{v}$)" for v in escaped_vals])
        elif 'startswith' in modifiers:
            return "".join([f"(?=^{v})" for v in escaped_vals])
        else:
            return "".join([f"(?=.*{v})" for v in escaped_vals])

    # Non-all path: keep wildcards, escape and convert
    escaped_vals = [re.escape(v).replace('\\*', '.*') for v in raw_vals]
    if 'endswith' in modifiers:
        escaped_vals = [f"{v}$" for v in escaped_vals]
    elif 'startswith' in modifiers:
        escaped_vals = [f"^{v}" for v in escaped_vals]

    if len(escaped_vals) > 1:
        return f"({'|'.join(escaped_vals)})"
    return escaped_vals[0]

def extract_fields_from_rule(rule: SigmaRule) -> Dict[str, str]:
    fields: Dict[str, List[str]] = {}

    for detection_name, detection in rule.detection.detections.items():
        for item in detection.detection_items:
            if not item.field:
                continue

            wazuh_field: str = item.field
            if wazuh_field == "CommandLine": wazuh_field = "win.eventdata.commandLine"
            elif wazuh_field == "Image": wazuh_field = "win.eventdata.image"
            elif wazuh_field == "file": wazuh_field = "syscheck.path"

            modifiers = [(m.__name__ if hasattr(m, '__name__') else m.__class__.__name__).lower().replace('sigma', '').replace('modifier', '') for m in item.modifiers] if item.modifiers else []
            compiled_val = process_modifiers(item.value, modifiers)

            if wazuh_field not in fields:
                fields[wazuh_field] = []
            fields[wazuh_field].append(compiled_val)

    final_fields: Dict[str, str] = {}
    for field, compiled_vals in fields.items():
        if len(compiled_vals) > 1:
            final_val = "".join([f"(?=.*{v})" if not v.startswith('(?=') else v for v in compiled_vals])
        else:
            final_val = compiled_vals[0]

        # Final safety check for cross-field AND combinations
        final_fields[field] = final_val.replace('.*.*', '.*')

    return final_fields

def main() -> None:
    logger.info("Starting pySigma Compilation to Wazuh XML...")

    if not os.path.exists(SIGMA_DIR):
        logger.error(f"CRITICAL: Directory {SIGMA_DIR} not found. Halting build.")
        sys.exit(1)

    # --- THE DIRTY BUILD DIRECTORY FIX ---
    if os.path.exists(BUILD_DIR):
        logger.info(f"Purging existing build directory: {BUILD_DIR}")
        shutil.rmtree(BUILD_DIR)
    os.makedirs(BUILD_DIR, exist_ok=True)
    # -------------------------------------

    count: int = 0
    skipped: int = 0
    yaml_files_found: int = 0

    for root_dir, _, files in os.walk(SIGMA_DIR):
        for filename in sorted(files):
            if not filename.endswith(('.yml', '.yaml')):
                continue

            yaml_files_found += 1
            filepath: str = os.path.join(root_dir, filename)

            with open(filepath, 'r') as f:
                yaml_content: str = f.read()

            try:
                collection = SigmaCollection.from_yaml(yaml_content)
            except SigmaError as e:
                logger.error(f"pySigma Validation Error in {filename}: {e}")
                skipped += 1
                continue

            for rule in collection.rules:
                if not isinstance(rule, SigmaRule):
                    skipped += 1
                    continue

                fields: Dict[str, str] = extract_fields_from_rule(rule)
                rule_uuid = str(rule.id)

                service: str = str(rule.logsource.service) if rule.logsource and rule.logsource.service else ''
                category: str = str(rule.logsource.category) if rule.logsource and rule.logsource.category else ''
                product: str = str(rule.logsource.product) if rule.logsource and rule.logsource.product else ''
                tags: List[str] = [str(tag.name) for tag in rule.tags] if rule.tags else []
                level: str = str(rule.level.name) if rule.level else 'low'

                # --- THE SINGLE SOURCE OF TRUTH FIX ---
                if 'wazuh_id' not in rule.custom_attributes:
                    logger.error(f"Validation Error: Rule '{rule.title}' ({rule_uuid}) is missing the required 'wazuh_id' attribute.")
                    skipped += 1
                    continue

                wazuh_id = str(rule.custom_attributes['wazuh_id'])
                # --------------------------------------

                xml_content: str = template.render(
                    product=product,
                    service=service,
                    rule_id=rule_uuid,
                    wazuh_id=wazuh_id,
                    wazuh_level=map_wazuh_level(level),
                    parent_group=get_parent_group(service, category, product),
                    fields=fields,
                    title=rule.title,
                    tags=tags
                )

                # --- THE XML VALIDATION FIX ---
                try:
                    import xml.etree.ElementTree as ET
                    ET.fromstring(xml_content)
                except ET.ParseError as e:
                    logger.error(f"Validation Error: Template generated malformed XML for rule '{rule.title}' ({rule_uuid}). Reason: {e}")
                    skipped += 1
                    continue
                # ------------------------------

                out_filename: str = filename.replace('.yml', '.xml').replace('.yaml', '.xml')
                with open(os.path.join(BUILD_DIR, out_filename), 'w') as out_f:
                    out_f.write(xml_content)

                count += 1

    logger.info(f"Successfully compiled {count} rules. Skipped {skipped} rules.")

    # --- STRICT COMPILATION SAFEGUARD ---
    if skipped > 0:
        logger.error(f"CRITICAL: {skipped} rule(s) failed compilation. Halting build to prevent partial deployment and accidental rule deletion.")
        sys.exit(1)

    if count == 0:
        logger.error("CRITICAL: No rules were compiled. Failing build to prevent wiping the SIEM.")
        sys.exit(1)
    # ------------------------------------

if __name__ == "__main__":
    main()
