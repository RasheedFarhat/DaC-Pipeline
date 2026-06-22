import os
import re
import logging
from typing import Dict, Any, Set, List
from jinja2 import Environment, FileSystemLoader
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

SIGMA_DIR: str = "rules/sigma"
BUILD_DIR: str = "build/wazuh"
TEMPLATE_DIR: str = "templates"

os.makedirs(BUILD_DIR, exist_ok=True)
env: Environment = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
template = env.get_template('wazuh_rule.xml.j2')

def map_wazuh_level(sigma_level: str) -> int:
    mapping: Dict[str, int] = {'informational': 3, 'low': 5, 'medium': 7, 'high': 10, 'critical': 12}
    return mapping.get(sigma_level.lower(), 5)

def get_parent_group(service: str) -> str:
    service_lower: str = service.lower() if service else ''
    if service_lower == 'sysmon': return 'sysmon_event1'
    if service_lower == 'syscheck': return 'syscheck'
    return 'syslog'

def is_logic_supported(parsed_condition: Any) -> bool:
    node_type: str = parsed_condition.__class__.__name__
    if node_type == "ConditionNOT":
        return False
    if hasattr(parsed_condition, 'args'):
        for arg in parsed_condition.args:
            if not is_logic_supported(arg):
                return False
    return True

def extract_fields_from_ast(rule: Any) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for detection_name, detection in rule.detection.detections.items():
        for item in detection.detection_items:
            if not item.field:
                continue

            wazuh_field: str = item.field
            if wazuh_field == "CommandLine": wazuh_field = "win.eventdata.commandLine"
            elif wazuh_field == "Image": wazuh_field = "win.eventdata.image"
            elif wazuh_field == "file": wazuh_field = "syscheck.path"

            values: List[str] = []
            for val in item.value:
                escaped_val: str = re.escape(str(val))
                val_str: str = escaped_val.replace('\\*', '.*')
                values.append(val_str)

            if len(values) > 1:
                fields[wazuh_field] = f"({'|'.join(values)})"
            elif len(values) == 1:
                fields[wazuh_field] = values[0]

    return fields

def main() -> None:
    logger.info("Starting pySigma AST Compilation to Wazuh XML...")

    if not os.path.exists(SIGMA_DIR):
        logger.error(f"Directory {SIGMA_DIR} not found. Skipping compilation.")
        return

    count: int = 0
    skipped: int = 0

    used_wazuh_ids: Set[str] = set()
    auto_id_counter: int = 100000

    for filename in sorted(os.listdir(SIGMA_DIR)):
        if not filename.endswith(('.yml', '.yaml')):
            continue

        filepath: str = os.path.join(SIGMA_DIR, filename)

        with open(filepath, 'r') as f:
            yaml_content: str = f.read()

        try:
            collection = SigmaCollection.from_yaml(yaml_content)
        except SigmaError as e:
            logger.error(f"pySigma Validation Error in {filename}: {e}")
            skipped += 1
            continue

        for rule in collection.rules:
            # --- MYPY FIX: Type Guard against Correlation Rules ---
            if not isinstance(rule, SigmaRule):
                logger.warning(f"Skipping unsupported Correlation Rule in {filename}.")
                skipped += 1
                continue

            parsed_condition_tree = rule.detection.parsed_condition[0].parsed

            if not is_logic_supported(parsed_condition_tree):
                logger.warning(f"Skipping {filename}: Contains unsupported logic (e.g., NOT).")
                skipped += 1
                continue

            fields: Dict[str, str] = extract_fields_from_ast(rule)

            # --- MYPY FIX: Force explicit string casting ---
            service: str = str(rule.logsource.service) if rule.logsource and rule.logsource.service else 'custom'
            product: str = str(rule.logsource.product) if rule.logsource and rule.logsource.product else 'custom'
            tags: List[str] = [str(tag.name) for tag in rule.tags] if rule.tags else []
            level: str = str(rule.level.name) if rule.level else 'low'

            if rule.custom_attributes and 'wazuh_id' in rule.custom_attributes:
                wazuh_id: str = str(rule.custom_attributes['wazuh_id'])
                used_wazuh_ids.add(wazuh_id)
            else:
                while str(auto_id_counter) in used_wazuh_ids:
                    auto_id_counter += 1
                wazuh_id = str(auto_id_counter)
                used_wazuh_ids.add(wazuh_id)

            xml_content: str = template.render(
                product=product,
                service=service,
                rule_id=rule.id,
                wazuh_id=wazuh_id,
                wazuh_level=map_wazuh_level(level),
                parent_group=get_parent_group(service),
                fields=fields,
                title=rule.title,
                tags=tags
            )

            out_filename: str = filename.replace('.yml', '.xml').replace('.yaml', '.xml')
            with open(os.path.join(BUILD_DIR, out_filename), 'w') as out_f:
                out_f.write(xml_content)

            logger.debug(f"Compiled: {filename} -> {out_filename}")
            count += 1

    logger.info(f"Successfully compiled {count} rules. Skipped {skipped} rules.")

if __name__ == "__main__":
    main()
