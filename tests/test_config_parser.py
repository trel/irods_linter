"""
Tests for the configuration parser module.

This module tests the ConfigParser class and its methods.
"""

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from linter.config_parser import ConfigParser
from linter.models import ConfigType


class TestConfigParser:
    """Test cases for ConfigParser."""

    def test_parse_file_valid_json(
        self, temp_config_file: Path, config_parser: ConfigParser
    ):
        """Test parsing a valid JSON configuration file."""
        result = config_parser.parse_file(temp_config_file)

        assert isinstance(result, dict)
        assert "_metadata" in result
        assert result["_metadata"]["file_path"] == temp_config_file
        assert "admin_password" in result
        assert result["admin_password"] == "rods"

    def test_parse_file_invalid_json(self, tmp_path: Path, config_parser: ConfigParser):
        """Test parsing an invalid JSON file raises appropriate error."""
        invalid_file = tmp_path / "invalid.json"
        with open(invalid_file, "w") as f:
            f.write('{"invalid": json}')  # Invalid JSON

        with pytest.raises(ValueError, match="Invalid JSON"):
            config_parser.parse_file(invalid_file)

    def test_parse_file_nonexistent(self, config_parser: ConfigParser):
        """Test parsing a non-existent file raises appropriate error."""
        nonexistent = Path("/nonexistent/file.json")

        with pytest.raises(ValueError, match="Failed to parse file"):
            config_parser.parse_file(nonexistent)

    def test_detect_config_type_unattended_installation(
        self, sample_config_data: Dict[str, Any]
    ):
        """Test detection of unattended installation configuration."""
        parser = ConfigParser()
        config_type = parser._detect_config_type(
            Path("test.json"), json.dumps(sample_config_data)
        )

        assert config_type == ConfigType.UNATTENDED_INSTALLATION

    def test_detect_config_type_server_config(self):
        """Test detection of server configuration."""
        server_config = {
            "schema_name": "server_config",
            "schema_version": "v5",
            "zone_name": "tempZone",
        }
        parser = ConfigParser()
        config_type = parser._detect_config_type(
            Path("server_config.json"), json.dumps(server_config)
        )

        assert config_type == ConfigType.SERVER_CONFIG

    def test_detect_config_type_by_filename(self):
        """Test configuration type detection by filename."""
        parser = ConfigParser()

        # Test unattended installation filename
        config_type = parser._detect_config_type(
            Path("unattended_installation.json"), '{"some": "data"}'
        )
        assert config_type == ConfigType.UNATTENDED_INSTALLATION

        # Test server config filename
        config_type = parser._detect_config_type(
            Path("server_config.json"), '{"some": "data"}'
        )
        assert config_type == ConfigType.SERVER_CONFIG

    def test_build_line_map(self, config_parser: ConfigParser):
        """Test building line map from JSON content."""
        content = """
{
    "admin_password": "test",
    "server_config": {
        "zone_key": "TEMPORARY_ZONE_KEY"
    }
}
"""
        config_parser._build_line_map(content)

        assert "admin_password" in config_parser.line_map
        assert "zone_key" in config_parser.line_map
        assert config_parser.line_map["admin_password"] == 3

    def test_get_line_number(
        self, config_parser: ConfigParser, line_map: Dict[str, int]
    ):
        """Test getting line number for JSON path."""
        config_parser.line_map = line_map

        # Test direct key lookup
        assert config_parser.get_line_number("admin_password") == 2

        # Test nested path
        assert config_parser.get_line_number("server_config.zone_key") == 57

        # Test missing key returns default
        assert config_parser.get_line_number("nonexistent_key") == 1

    def test_extract_sections(
        self, temp_config_file: Path, config_parser: ConfigParser
    ):
        """Test extracting configuration sections."""
        config_data = config_parser.parse_file(temp_config_file)
        sections = config_parser.extract_sections(config_data, temp_config_file)

        assert len(sections) > 0

        # Check that we have sections for main keys
        section_names = [section.name for section in sections]
        assert "admin_password" in section_names
        assert "server_config" in section_names
        assert "service_account_environment" in section_names
