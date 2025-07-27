"""
Rule loader for version-dependent iRODS configuration rules.

This module handles loading and parsing JSON-based rule definitions
for different iRODS versions.
"""

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from .rules import JsonRule


class RuleLoader:
    """Loads and manages version-specific rules from JSON files."""

    def __init__(self, rules_dir: Optional[Path] = None):
        if rules_dir is None:
            # Default to rules directory relative to this file
            self.rules_dir = Path(__file__).parent.parent / "rules" / "versions"
        else:
            self.rules_dir = Path(rules_dir)

    def get_available_versions(self) -> List[str]:
        """Get list of available iRODS versions with rule definitions."""
        versions = []
        if self.rules_dir.exists():
            for rule_file in self.rules_dir.glob("*.json"):
                version = rule_file.stem
                versions.append(version)
        return sorted(versions)

    def detect_version_from_config(self, config_data: Dict[str, Any]) -> Optional[str]:
        """
        Detect iRODS version from configuration data.

        Args:
            config_data: Configuration dictionary

        Returns:
            Detected version string or None if not found
        """
        # Try to find version in various config locations
        version_paths = [
            "server_config.icat_host_version",
            "service_account_environment.irods_version",
            "irods_version",
            "version",
        ]

        for path in version_paths:
            version = self._get_nested_value(config_data, path)
            if version:
                return self._normalize_version(str(version))

        # Try to detect from schema_version
        schema_version = self._get_nested_value(config_data, "schema_version")
        if schema_version:
            # Extract major version from schema (e.g., "v4" -> "4")
            if isinstance(schema_version, str) and schema_version.startswith("v"):
                major_version = schema_version[1:]
                if major_version.isdigit():
                    # Map schema version to latest minor version
                    version_mapping = {"3": "3.3.x", "4": "4.3.x", "5": "5.0.x"}
                    return version_mapping.get(major_version, "5.0.x")

        # If no version found, return None
        return None

    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Get a nested value from dictionary using dot notation."""
        keys = path.split(".")
        current = data

        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None

        return current

    def _normalize_version(self, version: str) -> str:
        """
        Normalize version string to match rule file naming.

        Examples:
            "4.0.3" -> "4.0.x"
            "4.2.12" -> "4.2.x"
            "5.0.1" -> "5.0.x"
        """
        # Extract major and minor version
        match = re.match(r"(\d+)\.(\d+)", version)
        if match:
            major, minor = match.groups()
            return f"{major}.{minor}.x"

        return version

    def load_rules_for_version(self, version: str) -> Dict[str, Any]:
        """
        Load rules for a specific iRODS version.

        Args:
            version: Version string (e.g., "4.3.x", "5.0.x")

        Returns:
            Dictionary containing rule definitions

        Raises:
            FileNotFoundError: If rule file for version doesn't exist
            json.JSONDecodeError: If rule file is invalid JSON
        """
        rule_file = self.rules_dir / f"{version}.json"

        if not rule_file.exists():
            # Try to find closest version
            closest = self._find_closest_version(version)
            if closest:
                rule_file = self.rules_dir / f"{closest}.json"
            else:
                raise FileNotFoundError(f"No rules found for version {version}")

        with open(rule_file, "r") as f:
            rules_data = json.load(f)

        return rules_data

    def load_rules(self, version: str) -> List["JsonRule"]:
        """
        Load rules for a specific version and return JsonRule objects.

        Args:
            version: Version string (e.g., "4.3.x", "5.0.x")

        Returns:
            List of JsonRule objects
        """
        from .rules import JsonRule  # Import here to avoid circular dependency

        rules_data = self.load_rules_for_version(version)
        json_rules = []

        for rule_data in rules_data.get("rules", []):
            if rule_data.get("enabled", True):
                json_rules.append(JsonRule(rule_data))

        return json_rules

    def _find_closest_version(self, target_version: str) -> Optional[str]:
        """Find the closest available version for the target version."""
        available = self.get_available_versions()

        # Extract version numbers for comparison
        def parse_version(v: str) -> Tuple[int, int]:
            match = re.match(r"(\d+)\.(\d+)", v)
            if match:
                return int(match.group(1)), int(match.group(2))
            return (0, 0)

        target_major, target_minor = parse_version(target_version)

        # Find exact match first
        normalized_target = f"{target_major}.{target_minor}.x"
        if normalized_target in available:
            return normalized_target

        # Find closest lower version
        best_match = None
        best_diff = float("inf")

        for version in available:
            major, minor = parse_version(version)

            # Only consider lower or equal versions
            if major < target_major or (
                major == target_major and minor <= target_minor
            ):
                diff = (target_major - major) * 10 + (target_minor - minor)
                if diff < best_diff:
                    best_diff = diff
                    best_match = version

        return best_match

    def get_rules_for_config(
        self, config_data: Dict[str, Any], version_override: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get appropriate rules for a configuration.

        Args:
            config_data: Configuration data
            version_override: Optional version override

        Returns:
            Rule definitions for the configuration
        """
        if version_override:
            version = self._normalize_version(version_override)
        else:
            version = self.detect_version_from_config(config_data)

        if not version:
            # Default to latest available version
            available = self.get_available_versions()
            if available:
                version = available[-1]  # Assume sorted order
            else:
                raise ValueError("No rule versions available")

        return self.load_rules_for_version(version)

    def validate_rule_file(self, rule_file: Path) -> List[str]:
        """
        Validate a rule file against the schema.

        Args:
            rule_file: Path to rule file

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        try:
            with open(rule_file, "r") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            return [f"Invalid JSON: {e}"]
        except Exception as e:
            return [f"Error reading file: {e}"]

        # Basic validation
        required_fields = ["version", "rules"]
        for field in required_fields:
            if field not in data:
                errors.append(f"Missing required field: {field}")

        if "rules" in data and isinstance(data["rules"], list):
            for i, rule in enumerate(data["rules"]):
                if not isinstance(rule, dict):
                    errors.append(f"Rule {i}: must be an object")
                    continue

                rule_required = ["id", "name", "description", "severity", "type"]
                for field in rule_required:
                    if field not in rule:
                        errors.append(f"Rule {i}: missing required field '{field}'")

                # Validate severity
                if "severity" in rule:
                    valid_severities = ["ERROR", "WARNING", "INFO"]
                    if rule["severity"] not in valid_severities:
                        errors.append(
                            f"Rule {i}: invalid severity '{rule['severity']}'"
                        )

                # Validate rule ID format
                if "id" in rule:
                    if not re.match(r"^[A-Z]{2,3}[0-9]{3}$", rule["id"]):
                        errors.append(f"Rule {i}: invalid ID format '{rule['id']}'")

        return errors

    def list_all_rules(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        List all rules across all versions.

        Returns:
            Dictionary mapping version to list of rules
        """
        all_rules = {}

        for version in self.get_available_versions():
            try:
                rules_data = self.load_rules_for_version(version)
                all_rules[version] = rules_data.get("rules", [])
            except Exception:
                # Skip versions that can't be loaded
                continue

        return all_rules
