"""
Integration tests for the main linter functionality.

This module tests the end-to-end functionality of the linter.
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

from irods_linter import IRODSLinter
from linter.models import Severity


class TestIRODSLinter:
    """Test cases for the main IRODSLinter class."""

    def test_lint_file_with_issues(self, temp_config_file: Path):
        """Test linting a file with known issues."""
        linter = IRODSLinter()
        results = linter.lint_file(temp_config_file)

        assert len(results) > 0

        # Should find multiple types of issues
        rule_ids = {result.rule_id for result in results}
        assert "SEC001" in rule_ids  # Security policy issues
        assert "SEC002" in rule_ids  # Weak passwords
        assert "SEC003" in rule_ids  # Default keys

    def test_lint_secure_file(self, tmp_path: Path, secure_config_data: Dict[str, Any]):
        """Test linting a secure configuration file."""
        secure_file = tmp_path / "secure_config.json"
        with open(secure_file, "w") as f:
            json.dump(secure_config_data, f, indent=2)

        linter = IRODSLinter()
        results = linter.lint_file(secure_file)

        # Should have no errors for secure config
        errors = [r for r in results if r.severity == Severity.ERROR]
        assert len(errors) == 0

    def test_lint_invalid_file(self, tmp_path: Path):
        """Test linting an invalid JSON file."""
        invalid_file = tmp_path / "invalid.json"
        with open(invalid_file, "w") as f:
            f.write('{"invalid": json}')

        linter = IRODSLinter()
        results = linter.lint_file(invalid_file)

        assert len(results) == 1
        assert results[0].rule_id == "PARSE_ERROR"
        assert results[0].severity == Severity.ERROR


class TestCommandLineInterface:
    """Test cases for the command-line interface."""

    def test_cli_help(self):
        """Test that CLI help works."""
        result = subprocess.run(
            [sys.executable, "irods_linter.py", "--help"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )

        assert result.returncode == 0
        assert "Lint iRODS configuration files" in result.stdout

    def test_cli_version(self):
        """Test that CLI version works."""
        result = subprocess.run(
            [sys.executable, "irods_linter.py", "--version"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )

        assert result.returncode == 0
        assert "1.0.0" in result.stdout

    def test_cli_lint_sample_file(self):
        """Test CLI on sample configuration file."""
        sample_file = (
            Path(__file__).parent.parent
            / "examples"
            / "sample_unattended_installation.json"
        )

        if sample_file.exists():
            result = subprocess.run(
                [sys.executable, "irods_linter.py", str(sample_file)],
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent,
            )

            # Should exit with error code due to issues found
            assert result.returncode == 1
            assert "SEC001" in result.stdout  # Should find security issues

    def test_cli_format_json(self):
        """Test CLI JSON output format."""
        sample_file = (
            Path(__file__).parent.parent
            / "examples"
            / "sample_unattended_installation.json"
        )

        if sample_file.exists():
            result = subprocess.run(
                [
                    sys.executable,
                    "irods_linter.py",
                    "--format",
                    "json",
                    str(sample_file),
                ],
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent,
            )

            # Should be valid JSON
            try:
                json.loads(result.stdout)
            except json.JSONDecodeError:
                pytest.fail("CLI JSON output is not valid JSON")

    def test_cli_severity_filter(self):
        """Test CLI severity filtering."""
        sample_file = (
            Path(__file__).parent.parent
            / "examples"
            / "sample_unattended_installation.json"
        )

        if sample_file.exists():
            # Test error-only filter
            result = subprocess.run(
                [
                    sys.executable,
                    "irods_linter.py",
                    "--severity",
                    "error",
                    str(sample_file),
                ],
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent,
            )

            # Should still find errors
            assert result.returncode == 1
            # Should not contain warnings
            assert "warning:" not in result.stdout

    def test_cli_exclude_rules(self):
        """Test CLI rule exclusion."""
        sample_file = (
            Path(__file__).parent.parent
            / "examples"
            / "sample_unattended_installation.json"
        )

        if sample_file.exists():
            result = subprocess.run(
                [
                    sys.executable,
                    "irods_linter.py",
                    "--exclude-rules",
                    "SEC002",
                    "--",
                    str(sample_file),
                ],
                capture_output=True,
                text=True,
                cwd=Path(__file__).parent.parent,
            )

            # Should not contain SEC002 results
            assert "SEC002" not in result.stdout

    def test_cli_nonexistent_file(self):
        """Test CLI with non-existent file."""
        result = subprocess.run(
            [sys.executable, "irods_linter.py", "nonexistent.json"],
            capture_output=True,
            text=True,
            cwd=Path(__file__).parent.parent,
        )

        assert result.returncode == 1
        assert "File not found" in result.stdout


@pytest.mark.skipif(
    not Path("examples/sample_unattended_installation.json").exists(),
    reason="Sample file not available",
)
class TestWithSampleFiles:
    """Test cases that require sample files to be present."""

    def test_sample_file_has_expected_issues(self):
        """Test that sample file contains expected security issues."""
        sample_file = Path("examples/sample_unattended_installation.json")
        linter = IRODSLinter()
        results = linter.lint_file(sample_file)

        # Extract rule IDs
        rule_ids = {result.rule_id for result in results}

        # Should contain known issues
        expected_rules = {"SEC001", "SEC002", "SEC003"}
        assert expected_rules.issubset(rule_ids)

    def test_secure_file_passes(self):
        """Test that secure configuration file passes."""
        secure_file = Path("examples/secure_unattended_installation.json")

        if secure_file.exists():
            linter = IRODSLinter()
            results = linter.lint_file(secure_file)

            # Should have no errors
            errors = [r for r in results if r.severity == Severity.ERROR]
            assert len(errors) == 0
