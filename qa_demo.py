#!/usr/bin/env python3
"""
Quality assurance demonstration script.

This script demonstrates the testing and code quality infrastructure
by running various checks and showing their output.
"""

import subprocess
import sys
from pathlib import Path


def run_command(cmd, description):
    """Run a command and display results."""
    print(f"\n{'='*60}")
    print(f"🔧 {description}")
    print("=" * 60)

    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, cwd=Path(__file__).parent
        )

        print(f"Command: {cmd}")
        print(f"Exit code: {result.returncode}")

        if result.stdout:
            print("\nSTDOUT:")
            print(result.stdout)

        if result.stderr:
            print("\nSTDERR:")
            print(result.stderr)

        return result.returncode == 0

    except Exception as e:
        print(f"Error running command: {e}")
        return False


def main():
    """Run quality assurance demonstration."""
    print("🧪 iRODS Configuration Linter - Quality Assurance Demo")
    print("======================================================")

    success_count = 0
    total_checks = 0

    checks = [
        # Core functionality
        ("make quick-test", "Running Core Linter Functionality"),
        # Test suite
        ("make test-quick", "Running Test Suite"),
        # Code formatting
        (".venv/bin/python -m black --check .", "Checking Code Formatting"),
        # Import sorting
        (".venv/bin/python -m isort --check-only .", "Checking Import Organization"),
        # Code linting
        (".venv/bin/python -m flake8 linter/ --count", "Running Code Linting"),
        # Type checking
        (
            ".venv/bin/python -m mypy linter/ --ignore-missing-imports",
            "Running Type Checking",
        ),
        # Security scanning
        (".venv/bin/python -m bandit -r linter/ -f json", "Running Security Scan"),
        # Coverage check
        (
            ".venv/bin/python -m pytest tests/ --cov=linter --cov-fail-under=80 --quiet",
            "Checking Test Coverage",
        ),
        # Example configurations
        (
            ".venv/bin/python irods_linter.py examples/secure_unattended_installation.json",
            "Testing Secure Configuration",
        ),
        # JSON validation
        (
            "python -c \"import json; [json.load(open(f)) for f in ['examples/sample_unattended_installation.json', 'examples/secure_unattended_installation.json']]\"",
            "Validating JSON Examples",
        ),
    ]

    for cmd, description in checks:
        total_checks += 1
        if run_command(cmd, description):
            success_count += 1
            print("✅ PASSED")
        else:
            print("❌ FAILED")

    print(f"\n{'='*60}")
    print(f"📊 SUMMARY")
    print("=" * 60)
    print(f"Total checks: {total_checks}")
    print(f"Passed: {success_count}")
    print(f"Failed: {total_checks - success_count}")
    print(f"Success rate: {success_count/total_checks*100:.1f}%")

    if success_count == total_checks:
        print("\n🎉 All quality checks passed! The project is ready for production.")
        return 0
    else:
        print(
            f"\n⚠️  {total_checks - success_count} checks failed. Please review the output above."
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
