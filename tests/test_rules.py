"""
Tests for the rules module.

This module tests individual rules and the rule engine.
"""

from pathlib import Path
from typing import Any, Dict

import pytest

from linter.models import LintResult, Severity
from linter.rules import (
    DatabaseConfigRule,
    FilePermissionsRule,
    InsecureKeysRule,
    PortConfigRule,
    RuleEngine,
    SecurityPolicyRule,
    WeakPasswordRule,
)


class TestSecurityPolicyRule:
    """Test cases for SecurityPolicyRule."""

    def test_detects_cs_neg_refuse_in_service_account(self, line_map: Dict[str, int]):
        """Test detection of CS_NEG_REFUSE in service account environment."""
        rule = SecurityPolicyRule()
        config_data = {
            "service_account_environment": {
                "irods_client_server_policy": "CS_NEG_REFUSE"
            }
        }

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert results[0].rule_id == "SEC001"
        assert results[0].severity == Severity.ERROR
        assert "CS_NEG_REFUSE" in results[0].message

    def test_detects_cs_neg_refuse_in_server_config(self, line_map: Dict[str, int]):
        """Test detection of CS_NEG_REFUSE in server config."""
        rule = SecurityPolicyRule()
        config_data = {"server_config": {"client_server_policy": "CS_NEG_REFUSE"}}

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert results[0].rule_id == "SEC001"
        assert "CS_NEG_REFUSE" in results[0].message

    def test_accepts_cs_neg_require(self, line_map: Dict[str, int]):
        """Test that CS_NEG_REQUIRE is accepted."""
        rule = SecurityPolicyRule()
        config_data = {
            "service_account_environment": {
                "irods_client_server_policy": "CS_NEG_REQUIRE"
            }
        }

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 0

    def test_detects_unknown_policy(self, line_map: Dict[str, int]):
        """Test detection of unknown policy values."""
        rule = SecurityPolicyRule()
        config_data = {
            "service_account_environment": {
                "irods_client_server_policy": "UNKNOWN_POLICY"
            }
        }

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert "Unknown client-server policy" in results[0].message


class TestWeakPasswordRule:
    """Test cases for WeakPasswordRule."""

    def test_detects_weak_admin_password(self, line_map: Dict[str, int]):
        """Test detection of weak admin passwords."""
        rule = WeakPasswordRule()
        config_data = {"admin_password": "rods"}

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert results[0].rule_id == "SEC002"
        assert results[0].severity == Severity.WARNING
        assert "rods" in results[0].message

    def test_detects_weak_database_password(self, line_map: Dict[str, int]):
        """Test detection of weak database passwords."""
        rule = WeakPasswordRule()
        config_data = {
            "server_config": {
                "plugin_configuration": {"database": {"password": "testpassword"}}
            }
        }

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert "testpassword" in results[0].message

    def test_accepts_strong_password(self, line_map: Dict[str, int]):
        """Test that strong passwords are accepted."""
        rule = WeakPasswordRule()
        config_data = {"admin_password": "StrongPassword123!@#"}

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 0


class TestInsecureKeysRule:
    """Test cases for InsecureKeysRule."""

    def test_detects_default_zone_key(self, line_map: Dict[str, int]):
        """Test detection of default zone key."""
        rule = InsecureKeysRule()
        config_data = {"server_config": {"zone_key": "TEMPORARY_ZONE_KEY"}}

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert results[0].rule_id == "SEC003"
        assert "Default zone key" in results[0].message

    def test_detects_default_negotiation_key(self, line_map: Dict[str, int]):
        """Test detection of default negotiation key."""
        rule = InsecureKeysRule()
        config_data = {
            "server_config": {"negotiation_key": "32_byte_server_negotiation_key__"}
        }

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert "Default negotiation key" in results[0].message

    def test_detects_short_zone_key(self, line_map: Dict[str, int]):
        """Test detection of short zone keys."""
        rule = InsecureKeysRule()
        config_data = {"server_config": {"zone_key": "short"}}

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert "too short" in results[0].message

    def test_detects_wrong_length_negotiation_key(self, line_map: Dict[str, int]):
        """Test detection of wrong length negotiation keys."""
        rule = InsecureKeysRule()
        config_data = {"server_config": {"negotiation_key": "too_short"}}

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert "exactly 32 characters" in results[0].message


class TestDatabaseConfigRule:
    """Test cases for DatabaseConfigRule."""

    def test_detects_localhost_without_ssl(self, line_map: Dict[str, int]):
        """Test detection of localhost database without SSL."""
        rule = DatabaseConfigRule()
        config_data = {
            "server_config": {
                "plugin_configuration": {"database": {"host": "localhost"}}
            }
        }

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) >= 1
        localhost_results = [r for r in results if "localhost" in r.message]
        assert len(localhost_results) == 1

    def test_detects_common_database_name(self, line_map: Dict[str, int]):
        """Test detection of common database names."""
        rule = DatabaseConfigRule()
        config_data = {
            "server_config": {"plugin_configuration": {"database": {"name": "ICAT"}}}
        }

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) >= 1
        name_results = [r for r in results if "common database name" in r.message]
        assert len(name_results) == 1


class TestPortConfigRule:
    """Test cases for PortConfigRule."""

    def test_detects_default_port(self, line_map: Dict[str, int]):
        """Test detection of default iRODS port."""
        rule = PortConfigRule()
        config_data = {"server_config": {"zone_port": 1247}}

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert "default iRODS port" in results[0].message

    def test_detects_large_port_range(self, line_map: Dict[str, int]):
        """Test detection of large port ranges."""
        rule = PortConfigRule()
        config_data = {
            "server_config": {
                "server_port_range_start": 20000,
                "server_port_range_end": 22000,  # 2000 port range
            }
        }

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert "Large port range" in results[0].message


class TestFilePermissionsRule:
    """Test cases for FilePermissionsRule."""

    def test_detects_world_readable_files(self, line_map: Dict[str, int]):
        """Test detection of world-readable file permissions."""
        rule = FilePermissionsRule()
        config_data = {"server_config": {"default_file_mode": "0644"}}

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert "world-readable" in results[0].message

    def test_detects_world_accessible_directories(self, line_map: Dict[str, int]):
        """Test detection of world-accessible directory permissions."""
        rule = FilePermissionsRule()
        config_data = {"server_config": {"default_dir_mode": "0755"}}

        results = rule.check(config_data, Path("test.json"), line_map)

        assert len(results) == 1
        assert "world access" in results[0].message


class TestRuleEngine:
    """Test cases for RuleEngine."""

    def test_applies_all_rules(self, sample_config_data: Dict[str, Any]):
        """Test that rule engine applies all rules."""
        engine = RuleEngine()
        results = engine.apply_rules(sample_config_data, Path("test.json"))

        # Should find multiple issues in sample config
        assert len(results) > 0

        # Check that different rule types are present
        rule_ids = {result.rule_id for result in results}
        assert "SEC001" in rule_ids  # Security policy
        assert "SEC002" in rule_ids  # Weak passwords
        assert "SEC003" in rule_ids  # Insecure keys

    def test_exclude_rules(self, sample_config_data: Dict[str, Any]):
        """Test excluding specific rules."""
        engine = RuleEngine()
        engine.exclude_rules(["SEC002"])  # Exclude password checks

        results = engine.apply_rules(sample_config_data, Path("test.json"))

        # Should not contain any SEC002 results
        rule_ids = {result.rule_id for result in results}
        assert "SEC002" not in rule_ids

    def test_only_rules(self, sample_config_data: Dict[str, Any]):
        """Test running only specific rules."""
        engine = RuleEngine()
        engine.only_rules(["SEC001"])  # Only security policy

        results = engine.apply_rules(sample_config_data, Path("test.json"))

        # Should only contain SEC001 results
        rule_ids = {result.rule_id for result in results}
        assert rule_ids == {"SEC001"}

    def test_secure_config_passes(self, secure_config_data: Dict[str, Any]):
        """Test that secure configuration passes all rules."""
        engine = RuleEngine()
        results = engine.apply_rules(secure_config_data, Path("test.json"))

        # Should have no errors for secure config
        errors = [r for r in results if r.severity == Severity.ERROR]
        assert len(errors) == 0

    def test_get_rule_info(self):
        """Test getting rule information."""
        engine = RuleEngine()
        rule_info = engine.get_rule_info()

        assert len(rule_info) > 0

        # Check structure of rule info
        for info in rule_info:
            assert "id" in info
            assert "name" in info
            assert "description" in info
            assert "severity" in info
            assert "tags" in info
