# Makefile for iRODS Configuration Linter

.PHONY: help install test demo clean lint format test-versions test-version-specific

# Default Python interpreter
PYTHON := python3
VENV := .venv
VENV_PYTHON := $(VENV)/bin/python
VENV_PIP := $(VENV)/bin/pip

# iRODS versions to test
IRODS_VERSIONS := 4.0.x 4.1.x 4.2.x 4.3.x 5.0.x

help:  ## Show this help message
	@echo "iRODS Configuration Linter"
	@echo "========================="
	@echo ""
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: $(VENV)  ## Set up the development environment
	$(VENV_PIP) install -r requirements.txt

$(VENV):
	$(PYTHON) -m venv $(VENV)
	$(VENV_PIP) install --upgrade pip

test: install  ## Run tests
	$(VENV_PYTHON) -m pytest tests/ -v

test-versions: install  ## Test all supported iRODS versions
	@echo "Testing version-dependent rule functionality for all iRODS versions..."
	@for version in $(IRODS_VERSIONS); do \
		echo "Testing iRODS version: $$version"; \
		$(VENV_PYTHON) -m pytest tests/test_rules.py::TestVersionSpecificRules::test_rules_load_for_all_versions -v -k "$$version" || exit 1; \
	done
	@echo "All version tests passed!"

test-version-specific: install  ## Run comprehensive version-specific tests
	$(VENV_PYTHON) -m pytest tests/test_rules.py::TestVersionSpecificRules -v

test-json-rules: install  ## Test JSON rule validation and loading
	$(VENV_PYTHON) -m pytest tests/test_rules.py::TestJsonRule -v
	$(VENV_PYTHON) -m pytest tests/test_rules.py::TestRuleLoader -v

validate-rule-files: install  ## Validate all JSON rule files against schema
	@echo "Validating JSON rule files..."
	@for version in $(IRODS_VERSIONS); do \
		echo "Validating rules for iRODS $$version"; \
		$(VENV_PYTHON) -c "from linter.rule_loader import RuleLoader; loader = RuleLoader(); rules = loader.load_rules('$$version'); print(f'✓ $$version: {len(rules)} rules loaded')"; \
	done

test-cov: install  ## Run tests with coverage
	$(VENV_PYTHON) -m pytest tests/ --cov=linter --cov-report=term-missing --cov-report=html

test-quick: install  ## Run quick tests (no coverage)
	$(VENV_PYTHON) -m pytest tests/ -x

demo: install  ## Run demonstration script
	$(VENV_PYTHON) demo.py

clean:  ## Clean up generated files
	rm -rf $(VENV)
	rm -rf __pycache__
	rm -rf linter/__pycache__
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -name "*~" -delete

lint: install  ## Run linter on examples
	$(VENV_PYTHON) irods_linter.py examples/*.json

lint-versions: install  ## Test linter with different iRODS versions
	@echo "Testing linter with different iRODS versions..."
	@for version in $(IRODS_VERSIONS); do \
		echo ""; \
		echo "=== Testing with iRODS $$version ==="; \
		$(VENV_PYTHON) irods_linter.py --irods-version $$version examples/sample_unattended_installation.json; \
	done

list-versions: install  ## List available iRODS versions
	$(VENV_PYTHON) irods_linter.py --list-versions

lint-table: install  ## Run linter with table output
	$(VENV_PYTHON) irods_linter.py --format table examples/sample_unattended_installation.json

lint-json: install  ## Run linter with JSON output
	$(VENV_PYTHON) irods_linter.py --format json examples/sample_unattended_installation.json

lint-errors: install  ## Show only errors
	$(VENV_PYTHON) irods_linter.py --severity error examples/sample_unattended_installation.json

format: install  ## Format code with black and isort
	$(VENV_PYTHON) -m black .
	$(VENV_PYTHON) -m isort .

lint-code: install  ## Lint Python code
	$(VENV_PYTHON) -m flake8 .
	$(VENV_PYTHON) -m mypy linter/
	$(VENV_PYTHON) -m bandit -r linter/

pre-commit-install: install  ## Install pre-commit hooks
	$(VENV_PYTHON) -m pre_commit install

pre-commit-run: install  ## Run pre-commit hooks on all files
	$(VENV_PYTHON) -m pre_commit run --all-files

ci: install format lint-code test-cov test-versions validate-rule-files  ## Run all CI checks locally

check-secure: install  ## Check the secure example configuration
	$(VENV_PYTHON) irods_linter.py examples/secure_unattended_installation.json

# Development shortcuts
dev-setup: install  ## Set up for development
	@echo "Development environment ready!"
	@echo "Run 'make demo' to see the linter in action"
	@echo "Run 'make lint' to check example configurations"

# Quick tests
quick-test: install  ## Quick test on sample file
	$(VENV_PYTHON) irods_linter.py examples/sample_unattended_installation.json
