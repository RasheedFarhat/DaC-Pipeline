.PHONY: test compile validate ci clean all install-hooks

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

# Symlinks the tracked hooks/pre-push into .git/hooks/ (not itself version-controlled --
# git hooks never are) so a fresh clone gets the same pre-push protection (tests +
# compile + validate) this repo's own history has relied on, not just CI-after-the-fact.
install-hooks:
	mkdir -p .git/hooks
	ln -sf ../../hooks/pre-push .git/hooks/pre-push
	chmod +x hooks/pre-push
	@echo "Installed hooks/pre-push -> .git/hooks/pre-push"

all: clean compile validate test
