"""
Test configuration fixtures and utilities.

This module provides common test fixtures and utilities used across
the test suite.
"""

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from linter.config_parser import ConfigParser
from linter.models import ConfigType, Severity
from linter.rules import RuleEngine


@pytest.fixture
def sample_config_data() -> Dict[str, Any]:
    """Provide sample configuration data for testing."""
    return {
        "admin_password": "rods",
        "default_resource_directory": "/var/lib/irods/Vault",
        "default_resource_name": "demoResc",
        "host_system_information": {
            "service_account_user_name": "irods",
            "service_account_group_name": "irods",
        },
        "service_account_environment": {
            "irods_client_server_policy": "CS_NEG_REFUSE",
            "irods_host": "irods-provider",
            "irods_zone_name": "tempZone",
            "schema_name": "service_account_environment",
            "schema_version": "v5",
        },
        "server_config": {
            "catalog_service_role": "provider",
            "client_server_policy": "CS_NEG_REFUSE",
            "default_dir_mode": "0755",
            "default_file_mode": "0644",
            "negotiation_key": "32_byte_server_negotiation_key__",
            "zone_key": "TEMPORARY_ZONE_KEY",
            "zone_port": 1247,
            "plugin_configuration": {
                "database": {
                    "host": "localhost",
                    "name": "ICAT",
                    "password": "testpassword",
                }
            },
            "schema_name": "server_config",
            "schema_version": "v5",
        },
    }


@pytest.fixture
def secure_config_data() -> Dict[str, Any]:
    """Provide secure configuration data for testing."""
    return {
        "admin_password": "StrongPassword123!@#",
        "default_resource_directory": "/var/lib/irods/Vault",
        "default_resource_name": "demoResc",
        "host_system_information": {
            "service_account_user_name": "irods",
            "service_account_group_name": "irods",
        },
        "service_account_environment": {
            "irods_client_server_policy": "CS_NEG_REQUIRE",
            "irods_host": "irods-provider",
            "irods_zone_name": "tempZone",
            "schema_name": "service_account_environment",
            "schema_version": "v5",
        },
        "server_config": {
            "catalog_service_role": "provider",
            "client_server_policy": "CS_NEG_REQUIRE",
            "default_dir_mode": "0750",
            "default_file_mode": "0600",
            "negotiation_key": "abc123def456ghi789jkl012mno345pq",
            "zone_key": "my_unique_zone_key_for_production_environment_123",
            "zone_port": 1300,
            "plugin_configuration": {
                "database": {
                    "host": "db-server.example.com",
                    "name": "irods_production_catalog",
                    "password": "SecureDbPassword789!",
                }
            },
            "schema_name": "server_config",
            "schema_version": "v5",
        },
    }


@pytest.fixture
def temp_config_file(tmp_path: Path, sample_config_data: Dict[str, Any]) -> Path:
    """Create a temporary configuration file for testing."""
    config_file = tmp_path / "test_config.json"
    with open(config_file, "w") as f:
        json.dump(sample_config_data, f, indent=2)
    return config_file


@pytest.fixture
def config_parser() -> ConfigParser:
    """Provide a configuration parser instance."""
    return ConfigParser()


@pytest.fixture
def rule_engine() -> RuleEngine:
    """Provide a rule engine instance."""
    return RuleEngine()


@pytest.fixture
def line_map() -> Dict[str, int]:
    """Provide a sample line map for testing."""
    return {
        "admin_password": 2,
        "irods_client_server_policy": 10,
        "client_server_policy": 33,
        "default_file_mode": 36,
        "default_dir_mode": 35,
        "negotiation_key": 40,
        "zone_key": 57,
        "zone_port": 59,
        "host": 44,
        "name": 45,
        "password": 47,
    }
