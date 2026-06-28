import os
import re
import sys
import yaml
import json
import shutil
import logging
from typing import Dict, Any, List
import xml.etree.ElementTree as ET

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.conditions import ConditionOR, ConditionAND, ConditionNOT

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

REGISTRY_FILE = "id_registry.json"

def load_config() -> Dict[str, str]:
    try:
        with open("pipeline.yaml", "r") as f:
            config = yaml.safe_load(f)
            return {
                "sigma_dir": config.get("build", {}).get("sigma_dir", "rules/sigma"),
                "wazuh_dir": config.get("build", {}).get("wazuh_dir", "build/wazuh"),
                "template_dir": config.get("build", {}).get("template_dir", "templates")
            }
    except FileNotFoundError:
        logger.warning("pipeline.yaml not found, falling back to defaults.")
        return {"sigma_dir": "rules/sigma", "wazuh_dir": "build/wazuh", "template_dir": "templates"}

CONFIG = load_config()
SIGMA_DIR = CONFIG["sigma_dir"]
BUILD_DIR = CONFIG["wazuh_dir"]
TEMPLATE_DIR = CONFIG["template_dir"]

env = Environment(
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

def extract_mitre_techniques(tag_names: List[str]) -> List[str]:
    """Reduce Sigma tags to the MITRE technique IDs Wazuh's <mitre><id> expects.

    Sigma tags mix tactics (attack.execution), techniques (attack.t1059.001),
    groups (attack.g0016), software, etc. Only technique tags map to a valid Wazuh
    MITRE id, so keep just `attack.t<digit>...` tags, strip the prefix, and upper-case
    them (T1059.001). Tactic-level and all other tags are dropped.
    """
    techniques: List[str] = []
    for name in tag_names:
        if re.match(r'attack\.t\d', name, re.IGNORECASE):
            techniques.append(name.replace('attack.', '').upper())
    return techniques

def _merge_literal(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Combine two literals on the same field within a single AND-clause.

    Wazuh ANDs all <field> elements in a rule and keys them by field name, so two
    conditions on one field must collapse into a single pattern:
      * both positive: conjunction via PCRE2 lookaheads (matches must co-occur).
      * both negated:  not A AND not B == not (A or B), so alternate the patterns
                       and keep negate=True.
      * mixed polarity: cannot be expressed as one keyed field; fail loudly rather
                       than emit a silently-wrong rule.
    """
    if existing["negate"] != new["negate"]:
        raise ValueError(
            "Cannot combine a positive and a negated match on the same field in one "
            "condition; rewrite the Sigma rule to use distinct fields."
        )
    if existing["negate"]:
        return {"pattern": f"(?:{existing['pattern']})|(?:{new['pattern']})", "negate": True}
    return {"pattern": f"(?=.*{existing['pattern']})(?=.*{new['pattern']})", "negate": False}

def _and_clauses(clause_lists: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """AND together several DNF operands by distributing into a flat DNF.

    Each operand is a list of AND-clauses (OR-linked). The AND of all operands is the
    cartesian product of their clauses, with same-field literals merged per clause.
    """
    import itertools
    result: List[Dict[str, Any]] = []
    for combo in itertools.product(*clause_lists):
        merged: Dict[str, Any] = {}
        for clause in combo:
            for field, literal in clause.items():
                if field in merged:
                    merged[field] = _merge_literal(merged[field], literal)
                else:
                    merged[field] = literal
        result.append(merged)
    return result

def evaluate_ast(node: Any, rule: SigmaRule) -> List[Dict[str, Any]]:
    """Recursively walks the Sigma AST.

    Each entry in the returned list is a dict mapping a Wazuh field name to
    {"pattern": str, "negate": bool}.  The list represents OR alternatives;
    multiple keys inside one dict represent AND conditions on the same rule.
    """
    if isinstance(node, ConditionOR):
        result = []
        for arg in node.args:
            result.extend(evaluate_ast(arg, rule))
        return result

    elif isinstance(node, ConditionAND):
        args_eval = [evaluate_ast(arg, rule) for arg in node.args]
        return _and_clauses(args_eval)

    elif isinstance(node, ConditionNOT):
        # De Morgan: NOT(c1 OR c2 OR ... cn) == NOT(c1) AND NOT(c2) AND ... NOT(cn).
        # The child is a DNF (list of AND-clauses). Negating one clause flips every
        # literal's polarity and turns its AND into an OR (a list of single-literal
        # clauses); ANDing those negated clauses back together via _and_clauses keeps
        # the result in DNF.
        child_evals = evaluate_ast(node.args[0], rule)
        negated_operands: List[List[Dict[str, Any]]] = []
        for clause in child_evals:
            alternatives = [
                {field: {"pattern": literal["pattern"], "negate": not literal["negate"]}}
                for field, literal in clause.items()
            ]
            if alternatives:
                negated_operands.append(alternatives)
        if not negated_operands:
            return [{}]
        return _and_clauses(negated_operands)

    else:
        from sigma.conditions import ConditionFieldEqualsValueExpression
        from sigma.types import SpecialChars

        if not isinstance(node, ConditionFieldEqualsValueExpression):
            logger.warning(f"Unknown AST node type at leaf: {type(node).__name__}")
            return [{}]

        field = node.field
        FIELD_MAPPINGS = {
            "CommandLine": "win.eventdata.commandLine",
            "Image": "win.eventdata.image",
            "file": "syscheck.path",
            "DestinationPort": "win.eventdata.destinationPort",
            "TargetObject": "win.eventdata.targetObject",
            "SourceIp": "win.eventdata.sourceIp",
        }
        wazuh_field = FIELD_MAPPINGS.get(field, field)

        starts_with_wildcard = node.value.startswith(SpecialChars.WILDCARD_MULTI)
        ends_with_wildcard = node.value.endswith(SpecialChars.WILDCARD_MULTI)

        parts = []
        for part in node.value:
            if part == SpecialChars.WILDCARD_MULTI:
                parts.append(".*")
            elif part == SpecialChars.WILDCARD_SINGLE:
                parts.append(".")
            else:
                parts.append(re.escape(str(part)))
        pattern = "".join(parts)

        if not starts_with_wildcard:
            pattern = "^" + pattern
        if not ends_with_wildcard:
            pattern = pattern + "$"

        return [{wazuh_field: {"pattern": pattern, "negate": False}}]

def load_registry() -> Dict[str, str]:
    try:
        with open(REGISTRY_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_registry(registry: Dict[str, str]):
    with open(REGISTRY_FILE, 'w') as f:
        json.dump(registry, f, indent=4, sort_keys=True)

def main() -> None:
    logger.info("Starting pySigma Compilation to Wazuh XML...")

    if not os.path.exists(SIGMA_DIR):
        logger.error(f"CRITICAL: Directory {SIGMA_DIR} not found. Halting build.")
        sys.exit(1)

    if os.path.exists(BUILD_DIR):
        logger.info(f"Purging existing build directory: {BUILD_DIR}")
        shutil.rmtree(BUILD_DIR)
    os.makedirs(BUILD_DIR, exist_ok=True)

    # Load ID Registry and find next available ID
    registry = load_registry()
    existing_ids = [int(v) for v in registry.values() if str(v).isdigit()]
    next_id = max(existing_ids) + 1 if existing_ids else 200000

    count = 0
    skipped = 0
    registry_updated = False

    for root_dir, _, files in os.walk(SIGMA_DIR):
        for filename in sorted(files):
            if not filename.endswith(('.yml', '.yaml')):
                continue

            filepath = os.path.join(root_dir, filename)
            with open(filepath, 'r') as f:
                yaml_content = f.read()

            try:
                collection = SigmaCollection.from_yaml(yaml_content)
            except SigmaError as e:
                logger.error(f"pySigma Validation Error in {filename}: {e}")
                skipped += 1
                continue

            for rule in collection.rules:
                # WE DELETED THE HARDCODED WAZUH_ID CHECK HERE!

                try:
                    rule_fields_list = evaluate_ast(rule.detection.parsed_condition[0].parsed, rule)
                except Exception as e:
                    logger.error(f"Failed to compile AST logic for {rule.id}: {e}")
                    skipped += 1
                    continue

                service = str(rule.logsource.service) if rule.logsource and rule.logsource.service else ''
                category = str(rule.logsource.category) if rule.logsource and rule.logsource.category else ''
                product = str(rule.logsource.product) if rule.logsource and rule.logsource.product else ''

                rule_uuid = str(rule.id)

                for idx, fields in enumerate(rule_fields_list):
                    # Deterministic Key: 'UUID' for the first rule, 'UUID_1', 'UUID_2' for splits
                    registry_key = rule_uuid if idx == 0 else f"{rule_uuid}_{idx}"

                    # Auto-assign ID from registry or generate a new one
                    if registry_key in registry:
                        current_wazuh_id = str(registry[registry_key])
                    else:
                        current_wazuh_id = str(next_id)
                        registry[registry_key] = current_wazuh_id
                        next_id += 1
                        registry_updated = True

                    xml_content = template.render(
                        product=product,
                        service=service,
                        rule_id=rule_uuid,
                        wazuh_id=current_wazuh_id,
                        wazuh_level=map_wazuh_level(str(rule.level.name) if rule.level else 'low'),
                        parent_group=get_parent_group(service, category, product),
                        fields=fields,
                        title=f"{rule.title} (Part {idx+1})" if len(rule_fields_list) > 1 else rule.title,
                        tags=extract_mitre_techniques([str(tag) for tag in rule.tags]) if rule.tags else []
                    )

                    try:
                        ET.fromstring(xml_content)
                    except ET.ParseError as e:
                        logger.error(f"Malformed XML for rule '{rule.title}'. Reason: {e}")
                        skipped += 1
                        continue

                    base_name = filename.replace('.yml', '').replace('.yaml', '')
                    out_filename = f"{base_name}_{current_wazuh_id}.xml"

                    with open(os.path.join(BUILD_DIR, out_filename), 'w') as out_f:
                        out_f.write(xml_content)

                    count += 1

    # Save the registry if we added new IDs
    if registry_updated:
        save_registry(registry)
        logger.info("Updated id_registry.json with new rule IDs.")

    logger.info(f"Successfully compiled {count} rules. Skipped {skipped} rules.")

    if skipped > 0:
        logger.error(f"CRITICAL: {skipped} rule(s) failed compilation. Halting build.")
        sys.exit(1)

    if count == 0:
        logger.error("CRITICAL: No rules were compiled. Failing build.")
        sys.exit(1)

if __name__ == "__main__":
    main()
