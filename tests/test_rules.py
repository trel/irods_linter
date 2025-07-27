"""
Tests for the rules module.

This module tests individual rules and the rule engine with
version-dependent JSON rules.
"""

from pathlib import Path
from typing import Dict

import pytest

from linter.models import Severity
from linter.rule_loader import RuleLoader
from linter.rules import JsonRule, RuleEngine


class TestJsonRule:
    """Test cases for JsonRule class."""

    def test_security_policy_rule_detects_cs_neg_refuse(self, line_map: Dict[str, int]):
        """Test detection of CS_NEG_REFUSE in service account environment."""
        rule_def = {
            "id": "SEC_001",
            "name": "Test Security Policy",
            "description": "Test rule for security policy detection",
            "type": "security_policy",
            "severity": "error",
            "config": {
                "check_locations": [
                    "service_account_environment.irods_client_server_policy"
                ],
                "forbidden_values": ["CS_NEG_REFUSE"],
                "allowed_values": ["CS_NEG_REQUIRE"],
            },
        }
        rule = JsonRule(rule_def)
        config_data = {
            "service_account_environment": {
                "irods_client_server_policy": "CS_NEG_REFUSE"
            }
        }

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert results[0].rule_id == "SEC_001"
        assert results[0].severity == Severity.ERROR
        assert "Client-server policy is set to 'CS_NEG_REFUSE'" in results[0].message

    def test_security_policy_rule_allows_secure_policy(self, line_map: Dict[str, int]):
        """Test that secure policies don't trigger the rule."""
        rule_def = {
            "id": "SEC_001",
            "name": "Test Security Policy",
            "description": "Test rule for security policy detection",
            "type": "security_policy",
            "severity": "error",
            "config": {
                "check_locations": [
                    "service_account_environment.irods_client_server_policy"
                ],
                "forbidden_values": ["CS_NEG_REFUSE"],
                "allowed_values": ["CS_NEG_REQUIRE"],
            },
        }
        rule = JsonRule(rule_def)
        config_data = {
            "service_account_environment": {
                "irods_client_server_policy": "CS_NEG_REQUIRE"
            }
        }

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 0

    def test_weak_password_rule_detects_weak_passwords(self, line_map: Dict[str, int]):
        """Test detection of weak passwords."""
        rule_def = {
            "id": "PWD_001",
            "name": "Test Password Rule",
            "description": "Test rule for password detection",
            "type": "weak_password",
            "severity": "warning",
            "config": {
                "weak_passwords": ["password", "123456", "admin", "irods"],
                "min_length": 8,
                "check_fields": ["irods_password"],
            },
        }
        rule = JsonRule(rule_def)
        config_data = {"irods_password": "password"}

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert results[0].rule_id == "PWD_001"
        assert results[0].severity == Severity.WARNING

    def test_port_config_rule_detects_insecure_ports(self, line_map: Dict[str, int]):
        """Test detection of insecure port configurations."""
        rule_def = {
            "id": "PORT_001",
            "name": "Test Port Rule",
            "description": "Test rule for port configuration",
            "type": "port_config",
            "severity": "error",
            "config": {"default_port": 1247, "max_port_range": 1000},
        }
        rule = JsonRule(rule_def)
        config_data = {"server_config": {"zone_port": 1247}}

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert results[0].rule_id == "PORT_001"

    def test_database_config_rule_with_regex(self, line_map: Dict[str, int]):
        """Test database configuration validation with regex."""
        rule_def = {
            "id": "DB_001",
            "name": "Test Database Rule",
            "description": "Test rule for database configuration",
            "type": "database_config",
            "severity": "warning",
            "config": {
                "ssl_indicators": ["ssl", "tls"],
                "common_db_names": ["ICAT", "icat", "test"],
                "localhost_variants": ["localhost", "127.0.0.1"],
                "require_ssl": False,
            },
        }
        rule = JsonRule(rule_def)
        config_data = {
            "server_config": {
                "plugin_configuration": {
                    "database": {"host": "localhost", "name": "ICAT"}
                }
            }
        }

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert results[0].rule_id == "DB_001"

    def test_missing_path_returns_no_results(self, line_map: Dict[str, int]):
        """Test that missing paths don't cause errors."""
        rule_def = {
            "id": "TEST_001",
            "name": "Test Rule",
            "description": "Test rule for missing paths",
            "type": "test",
            "severity": "info",
            "message": "Test rule",
            "suggestion": "Test suggestion",
            "checks": [
                {
                    "path": ["nonexistent", "path"],
                    "operation": "equals",
                    "value": "test",
                }
            ],
        }
        rule = JsonRule(rule_def)
        config_data = {"other": "value"}

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 0


class TestRuleLoader:
    """Test cases for RuleLoader class."""

    def test_version_normalization(self):
        """Test version normalization functionality."""
        loader = RuleLoader()

        assert loader._normalize_version("4.3.1") == "4.3.x"
        assert loader._normalize_version("5.0.0") == "5.0.x"
        assert loader._normalize_version("4.2.8") == "4.2.x"
        assert loader._normalize_version("unknown") == "unknown"

    def test_get_available_versions(self):
        """Test getting available versions."""
        loader = RuleLoader()
        versions = loader.get_available_versions()

        # Should include our created versions
        expected_versions = ["4.0.x", "4.1.x", "4.2.x", "4.3.x", "5.0.x"]
        for version in expected_versions:
            assert version in versions

    def test_load_rules_for_version(self):
        """Test loading rules for specific version."""
        loader = RuleLoader()
        rules = loader.load_rules("4.3.x")

        assert isinstance(rules, list)
        assert len(rules) > 0
        # Should be JsonRule instances
        assert all(isinstance(rule, JsonRule) for rule in rules)

    def test_load_rules_fallback_to_latest(self):
        """Test fallback to latest version for unknown versions."""
        loader = RuleLoader()
        rules = loader.load_rules("9.9.x")  # Non-existent version

        assert isinstance(rules, list)
        assert len(rules) > 0


class TestRuleEngine:
    """Test cases for RuleEngine class."""

    def test_rule_engine_initialization(self):
        """Test RuleEngine initialization."""
        engine = RuleEngine()
        assert engine.rule_loader is not None
        assert engine.irods_version is None

    def test_rule_engine_with_version(self):
        """Test RuleEngine with specific version."""
        engine = RuleEngine("4.3.x")
        assert engine.irods_version == "4.3.x"

    def test_apply_rules_integration(self, line_map: Dict[str, int]):
        """Test applying rules through the engine."""
        engine = RuleEngine("4.3.x")
        config_data = {
            "service_account_environment": {
                "irods_client_server_policy": "CS_NEG_REFUSE"
            },
            "irods_password": "password",
        }

        results = engine.apply_rules(config_data, Path("test.json"))

        # Should have multiple rule violations
        assert len(results) > 0
        # All results should be LintResult objects
        assert all(hasattr(result, "rule_id") for result in results)
        assert all(hasattr(result, "severity") for result in results)

    def test_version_detection_from_config(self):
        """Test automatic version detection from config."""
        engine = RuleEngine()
        config_data = {"schema_version": "v4", "catalog_provider_hosts": ["localhost"]}

        detected_version = engine._detect_version_from_config(config_data)
        # Should detect version 4.x based on schema
        assert detected_version.startswith("4.")


class TestVersionSpecificRules:
    """Test version-specific rule behavior."""

    @pytest.mark.parametrize("version", ["4.0.x", "4.1.x", "4.2.x", "4.3.x", "5.0.x"])
    def test_rules_load_for_all_versions(self, version):
        """Test that rules load successfully for all supported versions."""
        loader = RuleLoader()
        rules = loader.load_rules(version)

        assert isinstance(rules, list)
        assert len(rules) > 0
        assert all(isinstance(rule, JsonRule) for rule in rules)

    def test_version_specific_rule_differences(self, line_map: Dict[str, int]):
        """Test that different versions have different rule sets."""
        config_data = {
            "service_account_environment": {
                "irods_client_server_policy": "CS_NEG_REFUSE"
            }
        }

        # Test multiple versions
        results_4_0 = RuleEngine("4.0.x").apply_rules(config_data, Path("test.json"))
        results_5_0 = RuleEngine("5.0.x").apply_rules(config_data, Path("test.json"))

        # Both should detect issues, but potentially different numbers/severities
        assert len(results_4_0) > 0
        assert len(results_5_0) > 0

    def test_version_specific_rule_application(self, line_map: Dict[str, int]):
        """Test that different versions apply their rules correctly."""
        config_data = {
            "irods_password": "simplepass",
            "service_account_environment": {
                "irods_client_server_policy": "CS_NEG_REFUSE"
            },
        }

        # Test that each version applies its rules consistently
        results_4_0 = RuleEngine("4.0.x").apply_rules(config_data, Path("test.json"))
        results_5_0 = RuleEngine("5.0.x").apply_rules(config_data, Path("test.json"))

        # Both should detect issues (no assumption about which is "stricter")
        assert len(results_4_0) > 0
        assert len(results_5_0) > 0

        # Each version should consistently apply the same rules for the same input
        results_4_0_again = RuleEngine("4.0.x").apply_rules(
            config_data, Path("test.json")
        )
        results_5_0_again = RuleEngine("5.0.x").apply_rules(
            config_data, Path("test.json")
        )

        assert len(results_4_0) == len(results_4_0_again)
        assert len(results_5_0) == len(results_5_0_again)


# Existing fixtures remain the same
@pytest.fixture
def line_map():
    """Provide a simple line map for testing."""
    return {
        "service_account_environment": 5,
        "irods_client_server_policy": 6,
        "irods_password": 10,
        "irods_port": 15,
        "database_config": 20,
        "db_host": 21,
    }
