# Detection-as-Code (DaC) CI/CD Pipeline

## Overview
This repository houses a fully automated Detection-as-Code pipeline. It transitions SIEM rule management from a manual, UI-driven process into a version-controlled, automated, and tested engineering workflow.

By leveraging GitHub Actions and Python-based API integrations, this architecture ensures that all behavioral threat detections (Sigma/XML) are validated for syntax and logic errors before being programmatically deployed to a production Wazuh SIEM environment.

## Architecture & Workflow
1. **Authoring:** Security analysts write behavioral detection rules locally.
2. **Version Control:** Rules are committed and pushed to a remote branch.
3. **CI/CD Validation (GitHub Actions):** - A Python validation engine (`check_rule_ids.py`) scans the codebase.
   - It prevents pipeline continuation if duplicate Rule IDs or malformed YAML/XML structures are detected.
4. **Automated Deployment:** - Upon a successful merge to `main`, the deployment script (`deploy_rule.py`) authenticates with the Wazuh API.
   - It dynamically iterates through the rules directory, pushes all new/updated configurations, and safely restarts the SIEM analysis engine.

## Current Detections
* **T1220:** XSL Script Processing (WMIC AppLocker Bypass)
* *(Scalable to ingest hundreds of custom threat signatures)*

## Strategic Value
* **Risk Mitigation:** Eliminates manual "fat-finger" errors causing SIEM outages.
* **Traceability:** Every rule modification is tracked via Git commits and Pull Requests.
* **Operational Maturity:** Infrastructure manages deployment; analysts focus on threat intelligence.
