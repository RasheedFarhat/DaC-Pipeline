import os
import yaml
from jinja2 import Environment, FileSystemLoader

SIGMA_DIR = "rules/sigma"
BUILD_DIR = "build/wazuh"
TEMPLATE_DIR = "templates"

os.makedirs(BUILD_DIR, exist_ok=True)
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
template = env.get_template('wazuh_rule.xml.j2')

def sigma_level_to_wazuh(level):
    mapping = {'informational': 3, 'low': 5, 'medium': 7, 'high': 10, 'critical': 12}
    return mapping.get(level.lower(), 5)

def get_parent_group(logsource):
    service = logsource.get('service', '').lower()
    if service == 'sysmon': return 'sysmon_event1'
    if service == 'syscheck': return 'syscheck'
    return 'syslog'

def map_fields(selection_dict):
    fields = {}
    for key, val in selection_dict.items():
        # Strip Sigma modifiers (e.g., CommandLine|contains -> CommandLine)
        base_key = key.split('|')[0]
        
        wazuh_field = base_key
        if base_key == "CommandLine": wazuh_field = "win.eventdata.commandLine"
        elif base_key == "Image": wazuh_field = "win.eventdata.image"
        elif base_key == "file": wazuh_field = "syscheck.path"
            
        if isinstance(val, list):
            val = f"({'|'.join(val)})"
            
        fields[wazuh_field] = str(val).replace('*', '.*')
    return fields

def main():
    print("\n[*] Compiling Sigma YAML to Wazuh XML...")
    
    count = 0
    for filename in os.listdir(SIGMA_DIR):
        if not filename.endswith(('.yml', '.yaml')): continue
            
        filepath = os.path.join(SIGMA_DIR, filename)
        with open(filepath, 'r') as f:
            sigma_data = yaml.safe_load(f)
            
        rule_id = sigma_data.get('id') 
        wazuh_id = sigma_data.get('wazuh_id', '100000') # Extract custom field
        title = sigma_data.get('title', 'DaC Generated Rule')
        level = sigma_level_to_wazuh(sigma_data.get('level', 'low'))
        logsource = sigma_data.get('logsource', {})
        parent_group = get_parent_group(logsource)
        tags = sigma_data.get('tags', [])
        
        # Aggregate all selection blocks defensively
        selection_data = {}
        for k, v in sigma_data.get('detection', {}).items():
            if k.startswith('selection') and isinstance(v, dict):
                selection_data.update(v)
                
        fields = map_fields(selection_data)

        xml_content = template.render(
            product=logsource.get('product', 'custom'),
            service=logsource.get('service', 'custom'),
            rule_id=rule_id,
            wazuh_id=wazuh_id,
            wazuh_level=level,
            parent_group=parent_group,
            fields=fields,
            title=title,
            tags=tags
        )
        
        out_filename = filename.replace('.yml', '.xml').replace('.yaml', '.xml')
        with open(os.path.join(BUILD_DIR, out_filename), 'w') as out_f:
            out_f.write(xml_content)
            
        print(f"  -> {filename} compiled to build/wazuh/{out_filename}")
        count += 1
        
    print(f"[+] Successfully compiled {count} rules.")

if __name__ == "__main__":
    main()
