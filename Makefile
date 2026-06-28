.PHONY: test compile validate ci clean all

PYTHON = venv/bin/python3

test:
	$(PYTHON) -m pytest tests/ -v --tb=short

compile:
	$(PYTHON) scripts/compile_sigma.py

validate:
	$(PYTHON) scripts/check_rule_ids.py

ci:
	act push -W .github/workflows/integrate_rulesets.yml --secret-file .secrets

clean:
	rm -rf build/wazuh/

all: clean compile validate test
