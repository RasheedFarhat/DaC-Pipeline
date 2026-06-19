import os
import re
import logging
from jinja2 import Environment, FileSystemLoader
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

SIGMA_DIR = "rules/sigma"
BUILD_DIR = "build/wazuh"
TEMPLATE_DIR = "templates"

os.makedirs(BUILD_DIR, exist_ok=True)
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
template = env.get_template('wazuh_rule.xml.j2')

def map_wazuh_level(sigma_level):
    mapping = {'informational': 3, 'low': 5, 'medium': 7, 'high': 10, 'critical': 12}
    return mapping.get(sigma_level.lower(), 5)

def get_parent_group(service):
    service = service.lower() if service else ''
    if service == 'sysmon': return 'sysmon_event1'
    if service == 'syscheck': return 'syscheck'
    return 'syslog'

def is_logic_supported(parsed_condition):
    node_type = parsed_condition.__class__.__name__
    if node_type == "ConditionNOT":
        return False
    if hasattr(parsed_condition, 'args'):
        for arg in parsed_condition.args:
            if not is_logic_supported(arg):
                return False
    return True

def extract_fields_from_ast(rule):
    fields = {}
    for detection_name, detection in rule.detection.detections.items():
        for item in detection.detection_items:
            if not item.field:
                continue 
                
            wazuh_field = item.field
            if wazuh_field == "CommandLine": wazuh_field = "win.eventdata.commandLine"
            elif wazuh_field == "Image": wazuh_field = "win.eventdata.image"
            elif wazuh_field == "file": wazuh_field = "syscheck.path"
            
            values = []
            for val in item.value:
                # FIX: The Regex Trap. Escape regex metacharacters FIRST, 
                # then unescape the literal asterisk and turn it into a regex wildcard.
                escaped_val = re.escape(str(val))
                val_str = escaped_val.replace('\\*', '.*')
                values.append(val_str)
                
            if len(values) > 1:
                fields[wazuh_field] = f"({'|'.join(values)})"
            elif len(values) == 1:
                fields[wazuh_field] = values[0]
                
    return fields

def main():
    logger.info("Starting pySigma AST Compilation to Wazuh XML...")
    
    if not os.path.exists(SIGMA_DIR):
        logger.error(f"Directory {SIGMA_DIR} not found. Skipping compilation.")
        return

    count = 0
    skipped = 0
    
    # FIX: The ID Collision Tracker
    used_wazuh_ids = set()
    auto_id_counter = 100000
    
    # FIX: Deterministic parsing order using sorted()
    for filename in sorted(os.listdir(SIGMA_DIR)):
        if not filename.endswith(('.yml', '.yaml')): 
            continue
            
        filepath = os.path.join(SIGMA_DIR, filename)
        
        with open(filepath, 'r') as f:
            yaml_content = f.read()
        
        try:
            collection = SigmaCollection.from_yaml(yaml_content)
        except SigmaError as e:
            logger.error(f"pySigma Validation Error in {filename}: {e}")
            skipped += 1
            continue 

        for rule in collection.rules:
            parsed_condition_tree = rule.detection.parsed_condition[0].parsed
            
            if not is_logic_supported(parsed_condition_tree):
                logger.warning(f"Skipping {filename}: Contains unsupported logic (e.g., NOT).")
                skipped += 1
                continue

            fields = extract_fields_from_ast(rule)
            service = rule.logsource.service if rule.logsource else 'custom'
            product = rule.logsource.product if rule.logsource else 'custom'
            tags = [tag.name for tag in rule.tags] if rule.tags else []
            level = rule.level.name if rule.level else 'low'
            
            # --- ID ALLOCATION LOGIC ---
            # If a rule has a custom ID, log it so we don't accidentally overwrite it
            if rule.custom_attributes and 'wazuh_id' in rule.custom_attributes:
                wazuh_id = str(rule.custom_attributes['wazuh_id'])
                used_wazuh_ids.add(wazuh_id)
            else:
                # If no ID exists, increment our counter until we find an unused ID
                while str(auto_id_counter) in used_wazuh_ids:
                    auto_id_counter += 1
                wazuh_id = str(auto_id_counter)
                used_wazuh_ids.add(wazuh_id)
            # ---------------------------
            
            xml_content = template.render(
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
            
            out_filename = filename.replace('.yml', '.xml').replace('.yaml', '.xml')
            with open(os.path.join(BUILD_DIR, out_filename), 'w') as out_f:
                out_f.write(xml_content)
                
            logger.debug(f"Compiled: {filename} -> {out_filename}")
            count += 1
        
    logger.info(f"Successfully compiled {count} rules. Skipped {skipped} rules.")

if __name__ == "__main__":
    main()
