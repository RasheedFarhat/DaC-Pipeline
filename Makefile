.PHONY: test compile validate ci clean all

test:
	python3 -m pytest tests/ -v --tb=short

compile:
	python3 scripts/compile_sigma.py

validate:
	python3 scripts/check_rule_ids.py

ci:
	act push -W .github/workflows/integrate_rulesets.yml --secret-file .secrets

clean:
	rm -rf build/wazuh/

all: clean compile validate test
