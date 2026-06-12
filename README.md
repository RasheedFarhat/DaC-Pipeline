# Detection-as-Code (DaC) CI/CD Pipeline

## Overview

![Detection-as-Code Architecture Pipeline](./assets/MechanismFlowChart.png)

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
## Architectural Decisions & Known Limitations

**The "Source of Truth" Philosophy**
The core philosophy of this Detection-as-Code (DaC) pipeline is that Sigma (YAML) serves as the single source of truth for all threat intelligence. 

**pySigma Wazuh Compiler Limitation**
Currently, there is no official `pysigma-backend-wazuh` package published on the Python Package Index (PyPI). To maintain pipeline integrity without relying on unstable tooling, the architecture implements the following calculated tradeoff:

1. **Validation (CI):** Sigma rules are mathematically validated during the Pull Request phase using the `pysigma-backend-elasticsearch` module. This proves the YAML detection logic is sound, structurally correct, and fully compilable.
2. **Deployment (CD):** Because we cannot generate Wazuh XML on the fly via `pip` modules, the Wazuh-compatible `.xml` files are currently maintained in the `rules/wazuh/` directory. The deployment script (`deploy_rule.py`) idempotently pushes these XMLs to the Wazuh Manager via its REST API.

*Future Roadmap: Once a stable pySigma Wazuh backend is officially released, the XML files will be removed from version control entirely. The CI/CD pipeline will be updated to compile the XML artifacts dynamically directly from the Sigma source immediately before deployment.*
