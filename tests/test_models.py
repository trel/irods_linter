"""
Tests for the models module.

This module tests the data models and enums.
"""

from pathlib import Path

import pytest

from linter.models import (
    ConfigType,
    LinterConfig,
    LintResult,
    RuleDefinition,
    SecurityContext,
    Severity,
)


class TestSeverity:
    """Test cases for Severity enum."""

    def test_severity_values(self):
        """Test that severity enum has expected values."""
        assert Severity.ERROR.value == "error"
        assert Severity.WARNING.value == "warning"
        assert Severity.INFO.value == "info"
        assert Severity.STYLE.value == "style"


class TestConfigType:
    """Test cases for ConfigType enum."""

    def test_config_type_values(self):
        """Test that config type enum has expected values."""
        assert ConfigType.UNATTENDED_INSTALLATION.value == "unattended_installation"
        assert ConfigType.SERVER_CONFIG.value == "server_config"
        assert (
            ConfigType.SERVICE_ACCOUNT_ENVIRONMENT.value
            == "service_account_environment"
        )
        assert ConfigType.IRODS_ENVIRONMENT.value == "irods_environment"
        assert ConfigType.UNKNOWN.value == "unknown"


class TestLintResult:
    """Test cases for LintResult dataclass."""

    def test_lint_result_creation(self):
        """Test creating a LintResult."""
        result = LintResult(
            file_path=Path("test.json"),
            line_number=10,
            column=5,
            severity=Severity.ERROR,
            rule_id="TEST001",
            message="Test message",
            suggestion="Test suggestion",
        )

        assert result.file_path == Path("test.json")
        assert result.line_number == 10
        assert result.column == 5
        assert result.severity == Severity.ERROR
        assert result.rule_id == "TEST001"
        assert result.message == "Test message"
        assert result.suggestion == "Test suggestion"

    def test_lint_result_str(self):
        """Test string representation of LintResult."""
        result = LintResult(
            file_path=Path("test.json"),
            line_number=10,
            column=5,
            severity=Severity.ERROR,
            rule_id="TEST001",
            message="Test message",
        )

        str_repr = str(result)
        assert "test.json" in str_repr
        assert "line 10" in str_repr
        assert "column 5" in str_repr
        assert "error" in str_repr
        assert "TEST001" in str_repr
        assert "Test message" in str_repr

    def test_lint_result_without_column(self):
        """Test LintResult string representation without column."""
        result = LintResult(
            file_path=Path("test.json"),
            line_number=10,
            column=None,
            severity=Severity.WARNING,
            rule_id="TEST002",
            message="Test message",
        )

        str_repr = str(result)
        assert "test.json" in str_repr
        assert "line 10" in str_repr
        assert "column" not in str_repr


class TestRuleDefinition:
    """Test cases for RuleDefinition dataclass."""

    def test_rule_definition_creation(self):
        """Test creating a RuleDefinition."""
        rule_def = RuleDefinition(
            id="TEST001",
            name="Test Rule",
            description="A test rule",
            severity=Severity.ERROR,
            tags=["test", "security"],
        )

        assert rule_def.id == "TEST001"
        assert rule_def.name == "Test Rule"
        assert rule_def.description == "A test rule"
        assert rule_def.severity == Severity.ERROR
        assert rule_def.tags == ["test", "security"]
        assert rule_def.enabled is True

    def test_rule_definition_validation_empty_id(self):
        """Test that empty rule ID raises ValueError."""
        with pytest.raises(ValueError, match="Rule ID cannot be empty"):
            RuleDefinition(
                id="",
                name="Test Rule",
                description="A test rule",
                severity=Severity.ERROR,
                tags=[],
            )

    def test_rule_definition_validation_empty_name(self):
        """Test that empty rule name raises ValueError."""
        with pytest.raises(ValueError, match="Rule name cannot be empty"):
            RuleDefinition(
                id="TEST001",
                name="",
                description="A test rule",
                severity=Severity.ERROR,
                tags=[],
            )


class TestLinterConfig:
    """Test cases for LinterConfig dataclass."""

    def test_linter_config_creation(self):
        """Test creating a LinterConfig."""
        config = LinterConfig(
            enabled_rules={"SEC001", "SEC002"},
            disabled_rules={"NET001"},
            severity_overrides={"SEC001": Severity.WARNING},
            custom_rules_dirs=[Path("/custom")],
        )

        assert config.enabled_rules == {"SEC001", "SEC002"}
        assert config.disabled_rules == {"NET001"}
        assert config.severity_overrides == {"SEC001": Severity.WARNING}
        assert config.custom_rules_dirs == [Path("/custom")]

    def test_linter_config_default(self):
        """Test creating default LinterConfig."""
        config = LinterConfig.default()

        assert config.enabled_rules == set()
        assert config.disabled_rules == set()
        assert config.severity_overrides == {}
        assert config.custom_rules_dirs == []


class TestSecurityContext:
    """Test cases for SecurityContext dataclass."""

    def test_security_context_creation(self):
        """Test creating a SecurityContext."""
        context = SecurityContext(
            requires_ssl=True,
            allows_plaintext_passwords=False,
            requires_strong_keys=True,
            minimum_key_length=32,
        )

        assert context.requires_ssl is True
        assert context.allows_plaintext_passwords is False
        assert context.requires_strong_keys is True
        assert context.minimum_key_length == 32

    def test_security_context_strict(self):
        """Test creating strict SecurityContext."""
        context = SecurityContext.strict()

        assert context.requires_ssl is True
        assert context.allows_plaintext_passwords is False
        assert context.requires_strong_keys is True
        assert context.minimum_key_length == 32

    def test_security_context_permissive(self):
        """Test creating permissive SecurityContext."""
        context = SecurityContext.permissive()

        assert context.requires_ssl is False
        assert context.allows_plaintext_passwords is True
        assert context.requires_strong_keys is False
        assert context.minimum_key_length == 16
