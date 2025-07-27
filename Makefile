# Makefile for iRODS Configuration Linter

.PHONY: help install test demo clean lint format

# Default Python interpreter
PYTHON := python3
VENV := .venv
VENV_PYTHON := $(VENV)/bin/python
VENV_PIP := $(VENV)/bin/pip

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

ci: install format lint-code test-cov  ## Run all CI checks locally

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
