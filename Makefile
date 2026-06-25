.PHONY: test compile validate ci clean all

# Fast local checks
test:
	python3 -m pytest tests/ -v --tb=short

compile:
	python3 scripts/compile_sigma.py

validate:
	python3 scripts/check_rule_ids.py

# Full local CI simulation (Requires 'act' to be installed)
ci:
	act push -W .github/workflows/integrate_rulesets.yml

# Clean build artifacts
clean:
	rm -rf build/wazuh/

# Run everything in sequence
all: clean compile validate test
