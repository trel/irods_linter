"""
Configuration file parser for iRODS linter.

This module handles parsing of different iRODS configuration file formats
and extracts relevant metadata for linting.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import jsonschema
from jsonschema import ValidationError

from .models import ConfigSection, ConfigType


class ConfigParser:
    """Parses iRODS configuration files and extracts metadata."""

    def __init__(self):
        self.line_map: Dict[str, int] = {}
        self.config_type: ConfigType = ConfigType.UNKNOWN

    def parse_file(self, file_path: Path) -> Dict[str, Any]:
        """Parse a configuration file and return the data with metadata."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Build line mapping for error reporting
            self._build_line_map(content)

            # Detect configuration type
            self.config_type = self._detect_config_type(file_path, content)

            # Parse JSON
            config_data = json.loads(content)

            # Add metadata
            config_data["_metadata"] = {
                "file_path": file_path,
                "config_type": self.config_type,
                "line_map": self.line_map,
            }

            return config_data

        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
        except Exception as e:
            raise ValueError(f"Failed to parse file: {e}")

    def _build_line_map(self, content: str) -> None:
        """Build mapping of JSON paths to line numbers."""
        self.line_map = {}
        lines = content.split("\n")

        # Simple approach: map keys to line numbers
        # This is a simplified version - a full implementation would use a proper JSON parser
        # with location tracking
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if ":" in line and not line.startswith("//") and not line.startswith("#"):
                # Extract key from line like '"key": value'
                match = re.match(r'\s*"([^"]+)"\s*:', line)
                if match:
                    key = match.group(1)
                    self.line_map[key] = line_num

    def _detect_config_type(self, file_path: Path, content: str) -> ConfigType:
        """Detect the type of iRODS configuration file."""
        # Try to parse as JSON first
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return ConfigType.UNKNOWN

        # Check for schema indicators
        schema_name = data.get("schema_name", "")

        if schema_name == "service_account_environment":
            return ConfigType.SERVICE_ACCOUNT_ENVIRONMENT
        elif schema_name == "server_config":
            return ConfigType.SERVER_CONFIG
        elif schema_name == "irods_environment":
            return ConfigType.IRODS_ENVIRONMENT

        # Check for unattended installation specific keys
        if all(
            key in data
            for key in ["admin_password", "host_system_information", "server_config"]
        ):
            return ConfigType.UNATTENDED_INSTALLATION

        # Check filename patterns
        filename = file_path.name.lower()
        if "unattended" in filename:
            return ConfigType.UNATTENDED_INSTALLATION
        elif "server_config" in filename:
            return ConfigType.SERVER_CONFIG
        elif "irods_environment" in filename:
            return ConfigType.IRODS_ENVIRONMENT
        elif "service_account" in filename:
            return ConfigType.SERVICE_ACCOUNT_ENVIRONMENT

        return ConfigType.UNKNOWN

    def get_line_number(self, json_path: str) -> int:
        """Get line number for a given JSON path."""
        # Simple implementation - extract the key from the path
        if "." in json_path:
            key = json_path.split(".")[-1]
        else:
            key = json_path

        return self.line_map.get(key, 1)

    def extract_sections(
        self, config_data: Dict[str, Any], file_path: Path
    ) -> List[ConfigSection]:
        """Extract configuration sections with metadata."""
        sections = []

        def _extract_recursive(
            data: Any, path: str = "", parent: Optional[str] = None
        ) -> None:
            if isinstance(data, dict):
                for key, value in data.items():
                    if key == "_metadata":
                        continue

                    current_path = f"{path}.{key}" if path else key
                    line_num = self.get_line_number(current_path)

                    section = ConfigSection(
                        name=current_path,
                        data=value,
                        line_number=line_num,
                        source_file=file_path,
                        parent_section=parent,
                    )
                    sections.append(section)

                    if isinstance(value, (dict, list)):
                        _extract_recursive(value, current_path, current_path)

            elif isinstance(data, list):
                for i, item in enumerate(data):
                    if isinstance(item, (dict, list)):
                        _extract_recursive(item, f"{path}[{i}]", path)

        _extract_recursive(config_data)
        return sections


class SchemaValidator:
    """Validates iRODS configuration against schemas."""

    def __init__(self):
        self.schemas = self._load_schemas()

    def _load_schemas(self) -> Dict[ConfigType, Dict]:
        """Load JSON schemas for different config types."""
        # This is a simplified version - in production you'd load actual schema files
        schemas = {}

        # Unattended installation schema (simplified)
        schemas[ConfigType.UNATTENDED_INSTALLATION] = {
            "type": "object",
            "properties": {
                "admin_password": {"type": "string"},
                "default_resource_directory": {"type": "string"},
                "default_resource_name": {"type": "string"},
                "host_system_information": {
                    "type": "object",
                    "properties": {
                        "service_account_user_name": {"type": "string"},
                        "service_account_group_name": {"type": "string"},
                    },
                    "required": [
                        "service_account_user_name",
                        "service_account_group_name",
                    ],
                },
                "server_config": {"type": "object"},
                "service_account_environment": {"type": "object"},
            },
            "required": [
                "admin_password",
                "default_resource_name",
                "host_system_information",
                "server_config",
                "service_account_environment",
            ],
        }

        return schemas

    def validate(
        self, config_data: Dict[str, Any], config_type: ConfigType
    ) -> List[str]:
        """Validate configuration against schema."""
        errors = []

        if config_type not in self.schemas:
            return ["No schema available for configuration type"]

        try:
            jsonschema.validate(config_data, self.schemas[config_type])
        except ValidationError as e:
            errors.append(f"Schema validation error: {e.message}")

        return errors
