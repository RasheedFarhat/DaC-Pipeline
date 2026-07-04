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
            build = config.get("build", {})
            return {
                "sigma_dir": build.get("sigma_dir", "rules/sigma"),
                "wazuh_dir": build.get("wazuh_dir", "build/wazuh"),
                "template_dir": build.get("template_dir", "templates"),
                "field_mappings": build.get("field_mappings", "field_mappings.yaml"),
            }
    except FileNotFoundError:
        logger.warning("pipeline.yaml not found, falling back to defaults.")
        return {"sigma_dir": "rules/sigma", "wazuh_dir": "build/wazuh",
                "template_dir": "templates", "field_mappings": "field_mappings.yaml"}

# Minimal built-in fallback used only if the external mapping file is missing.
DEFAULT_FIELD_MAPPINGS: Dict[str, str] = {
    "CommandLine": "win.eventdata.commandLine",
    "Image": "win.eventdata.image",
    "file": "syscheck.path",
}

def load_field_mappings(path: str) -> Dict[str, str]:
    """Load the Sigma->Wazuh field name map from an external YAML file.

    Keeping the map in a data file (rather than a code literal) lets rule authors
    extend coverage without touching the compiler. Falls back to a minimal built-in
    set if the file is missing or malformed.
    """
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        logger.warning(f"{path} not found; using built-in field mappings.")
        return dict(DEFAULT_FIELD_MAPPINGS)
    if not isinstance(data, dict) or not data:
        logger.warning(f"{path} is empty or not a mapping; using built-in field mappings.")
        return dict(DEFAULT_FIELD_MAPPINGS)
    return {str(k): str(v) for k, v in data.items()}

CONFIG = load_config()
SIGMA_DIR = CONFIG["sigma_dir"]
BUILD_DIR = CONFIG["wazuh_dir"]
TEMPLATE_DIR = CONFIG["template_dir"]
FIELD_MAPPINGS = load_field_mappings(CONFIG["field_mappings"])

env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(['xml', 'j2']),
    # Strip the {% for %}/{% if %} control lines from the output instead of
    # leaving a blank line for each -- the XML is what reviewers download from CI.
    trim_blocks=True,
    lstrip_blocks=True,
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

def _merge_field_literals(existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Combine two lists of literals for the SAME Wazuh field within one AND-clause.

    Wazuh ANDs every <field> element in a rule, so a field may appear more than once:
      * same polarity collapses into one literal (positives via PCRE2 lookahead
        conjunction, negatives via alternation under a single negate="yes").
      * a positive and a negated literal coexist as two separate <field> elements
        (Wazuh ANDs them: "matches A and does not match B") — the common
        `selection and not filter` exclusion pattern.
    """
    result: List[Dict[str, Any]] = [dict(lit) for lit in existing]
    for lit in incoming:
        same = next((e for e in result if e["negate"] == lit["negate"]), None)
        if same is None:
            result.append(dict(lit))
        elif lit["negate"]:
            same["pattern"] = f"(?:{same['pattern']})|(?:{lit['pattern']})"
        else:
            same["pattern"] = f"(?=.*{same['pattern']})(?=.*{lit['pattern']})"
    return result

MAX_AND_CLAUSE_PRODUCT = 500

def _and_clauses(clause_lists: List[List[Dict[str, List[Dict[str, Any]]]]]) -> List[Dict[str, List[Dict[str, Any]]]]:
    """AND together several DNF operands by distributing into a flat DNF.

    Each operand is a list of AND-clauses (OR-linked). The AND of all operands is the
    cartesian product of their clauses; same-field literals are merged per clause.
    """
    import itertools
    import math

    product_size = math.prod(len(clauses) for clauses in clause_lists) if clause_lists else 1
    if product_size > MAX_AND_CLAUSE_PRODUCT:
        raise ValueError(
            f"AND clause cartesian product too large ({product_size} > "
            f"{MAX_AND_CLAUSE_PRODUCT}): this Sigma rule's nested OR/AND structure "
            f"would explode into too many DNF clauses to compile safely. Simplify the "
            f"rule's condition logic."
        )

    result: List[Dict[str, List[Dict[str, Any]]]] = []
    for combo in itertools.product(*clause_lists):
        merged: Dict[str, List[Dict[str, Any]]] = {}
        for clause in combo:
            for field, literals in clause.items():
                if field in merged:
                    merged[field] = _merge_field_literals(merged[field], literals)
                else:
                    merged[field] = [dict(lit) for lit in literals]
        result.append(merged)
    return result

# Sigma modifiers the AST walker cannot translate to a sound PCRE2 match. They must
# fail the build loudly rather than emit a wrong rule. |base64/|base64offset are the
# dangerous case: by the time the value reaches the leaf, pySigma has already applied
# the modifier, so a |base64 value is an ordinary string and the walker would happily
# compile it to an exact-match on the *encoded* literal — a silent false negative.
# Catching it here, by modifier name, is the only place that information survives.
UNSUPPORTED_MODIFIERS: Dict[str, str] = {
    "SigmaBase64Modifier": "base64",
    "SigmaBase64OffsetModifier": "base64offset",
}

def _iter_detection_items(detection: Any) -> Any:
    """Yield every SigmaDetectionItem under a SigmaDetection, recursing into nests."""
    from sigma.rule import SigmaDetection
    for element in detection.detection_items:
        if isinstance(element, SigmaDetection):
            yield from _iter_detection_items(element)
        else:
            yield element

def assert_supported_constructs(rule: SigmaRule) -> None:
    """Fail loudly on Sigma features the compiler cannot soundly translate.

    Some unsupported constructs are invisible at the AST leaf because pySigma has
    already rewritten the value (notably |base64, which leaves an ordinary string).
    Catch those here, before the walk, by inspecting each detection item's modifiers
    so the build stops with a clear message instead of shipping a false-negative rule.
    """
    if not rule.detection or not rule.detection.detections:
        return
    for selection_name, detection in rule.detection.detections.items():
        for item in _iter_detection_items(detection):
            for modifier in getattr(item, "modifiers", None) or []:
                name = getattr(modifier, "__name__", str(modifier))
                if name in UNSUPPORTED_MODIFIERS:
                    raise NotImplementedError(
                        f"Unsupported Sigma modifier '|{UNSUPPORTED_MODIFIERS[name]}' on "
                        f"field '{getattr(item, 'field', '?')}' in selection "
                        f"'{selection_name}': not implemented. It would compile to an "
                        f"exact-match on the encoded literal — a silent false-negative "
                        f"detection. Remove the modifier or add real support before "
                        f"shipping this rule."
                    )

def evaluate_ast(node: Any, rule: SigmaRule) -> List[Dict[str, List[Dict[str, Any]]]]:
    """Recursively walks the Sigma AST.

    Each entry in the returned list is one OR-alternative (a rule). A rule maps each
    Wazuh field name to a LIST of {"pattern": str, "negate": bool} literals; a field
    may carry more than one literal (e.g. a positive match plus a negated exclusion),
    which the template renders as multiple <field> elements ANDed by Wazuh.
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
        negated_operands: List[List[Dict[str, List[Dict[str, Any]]]]] = []
        for clause in child_evals:
            alternatives = [
                {field: [{"pattern": literal["pattern"], "negate": not literal["negate"]}]}
                for field, literals in clause.items()
                for literal in literals
            ]
            if alternatives:
                negated_operands.append(alternatives)
        if not negated_operands:
            return [{}]
        return _and_clauses(negated_operands)

    else:
        from sigma.conditions import ConditionFieldEqualsValueExpression
        from sigma.types import SpecialChars, SigmaString, SigmaNull

        # A non-field leaf (e.g. a field-less keyword match) would otherwise fall
        # through to a rule with ZERO <field> elements — one that matches every event
        # in the parent group and floods the SIEM. Reject it loudly instead.
        if not isinstance(node, ConditionFieldEqualsValueExpression):
            raise NotImplementedError(
                f"Unsupported Sigma construct: leaf node '{type(node).__name__}' "
                f"(e.g. a field-less keyword match). It would emit a rule with no "
                f"<field> constraints that matches every event. Rewrite the detection "
                f"using explicit field:value pairs."
            )

        field = node.field
        value = node.value
        wazuh_field = FIELD_MAPPINGS.get(field, field)

        # A null value cannot be soundly compiled to a string match.
        if isinstance(value, SigmaNull):
            raise ValueError(
                f"Field '{field}' has a null value, which cannot be compiled to a "
                f"match. Give the field a concrete value."
            )
        # Numeric comparisons (|lt/|gt…), |re, |cidr and |base64offset arrive as value
        # types the walker can't translate. Reject by type rather than crash later on a
        # missing string method (the old AttributeError) or emit a wrong rule.
        if not isinstance(value, SigmaString):
            raise NotImplementedError(
                f"Unsupported Sigma value type '{type(value).__name__}' on field "
                f"'{field}' (e.g. numeric comparison, |re, |cidr, |base64offset). The "
                f"compiler only supports plain string matching; these are not "
                f"implemented and must not silently produce a wrong rule."
            )
        # An empty value would compile to '(?i)^$' and match only an empty field —
        # almost certainly unintended, and silent. Reject it.
        if len(value) == 0:
            raise ValueError(
                f"Field '{field}' has an empty value, which would compile to '(?i)^$' "
                f"and match only an empty field — almost certainly unintended. Give the "
                f"field a concrete value."
            )

        starts_with_wildcard = value.startswith(SpecialChars.WILDCARD_MULTI)
        ends_with_wildcard = value.endswith(SpecialChars.WILDCARD_MULTI)

        parts = []
        # value.s is SigmaString's canonical parts tuple (plain-string runs and
        # SpecialChars); re.escape is per-character, so escaping whole runs emits
        # the same pattern as escaping char-by-char.
        for part in value.s:
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

        # Sigma string matching is case-insensitive by default, but Wazuh's pcre2
        # field type is case-sensitive. Prefix an inline (?i) so a casing variant
        # (e.g. CertUtil.exe vs certutil.exe) can't silently evade the detection.
        pattern = "(?i)" + pattern

        return [{wazuh_field: [{"pattern": pattern, "negate": False}]}]

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
                # A Sigma correlation rule has no detection AST to walk. Reject it
                # loudly, like every other unsupported construct, instead of
                # crashing mid-compile on a missing attribute.
                if not isinstance(rule, SigmaRule):
                    logger.error(
                        f"Unsupported rule type '{type(rule).__name__}' in {filename}: "
                        f"only standard Sigma detection rules can be compiled."
                    )
                    skipped += 1
                    continue

                try:
                    assert_supported_constructs(rule)
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
