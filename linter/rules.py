"""Rule engine for iRODS configuration linting.

This module contains the rule definitions and the engine that applies them
to configuration data. Rules are now loaded from JSON files based on
iRODS version for maximum flexibility.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import LintResult, SecurityContext, Severity
from .rule_loader import RuleLoader


class Rule(ABC):
    """Abstract base class for linting rules."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: Severity,
        tags: List[str] = None,
        documentation_url: Optional[str] = None,
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.tags = tags or []
        self.documentation_url = documentation_url
        self.enabled = True

    @abstractmethod
    def check(
        self,
        config_data: Dict[str, Any],
        file_path: Path,
        line_map: Dict[str, int] = None,
    ) -> List[LintResult]:
        """Check the configuration and return any issues found."""
        pass

    def _create_result(
        self,
        file_path: Path,
        key_path: str,
        message: str,
        suggestion: str = None,
        line_map: Dict[str, int] = None,
    ) -> LintResult:
        """Helper to create a LintResult."""
        line_number = 1
        if line_map and key_path:
            # Try different variations of the key path
            for key in [key_path, key_path.split(".")[-1]]:
                if key in line_map:
                    line_number = line_map[key]
                    break

        return LintResult(
            file_path=file_path,
            line_number=line_number,
            column=None,
            severity=self.severity,
            rule_id=self.rule_id,
            message=message,
            suggestion=suggestion,
            documentation_url=self.documentation_url,
        )


class SecurityPolicyRule(Rule):
    """Rule to check client-server security policy."""

    def __init__(self):
        super().__init__(
            rule_id="SEC001",
            name="Secure Client-Server Policy",
            description="Client-server policy should require SSL/TLS connections",
            severity=Severity.ERROR,
            tags=["security", "ssl", "communication"],
            documentation_url="https://docs.irods.org/latest/system_overview/tls/",
        )

    def check(
        self,
        config_data: Dict[str, Any],
        file_path: Path,
        line_map: Dict[str, int] = None,
    ) -> List[LintResult]:
        results = []

        # Check in different locations where this setting might appear
        policies_to_check = [
            (
                "service_account_environment.irods_client_server_policy",
                config_data.get("service_account_environment", {}).get(
                    "irods_client_server_policy"
                ),
            ),
            (
                "server_config.client_server_policy",
                config_data.get("server_config", {}).get("client_server_policy"),
            ),
            (
                "irods_client_server_policy",
                config_data.get("irods_client_server_policy"),
            ),
        ]

        for key_path, policy_value in policies_to_check:
            if policy_value is not None:
                if policy_value == "CS_NEG_REFUSE":
                    results.append(
                        self._create_result(
                            file_path=file_path,
                            key_path=key_path,
                            message=(
                                "Client-server policy is set to 'CS_NEG_REFUSE' "
                                "which allows unencrypted connections"
                            ),
                            suggestion=(
                                "Change to 'CS_NEG_REQUIRE' to enforce SSL/TLS "
                                "encryption for all connections"
                            ),
                            line_map=line_map,
                        )
                    )
                elif policy_value not in ["CS_NEG_REQUIRE", "CS_NEG_DONT_CARE"]:
                    results.append(
                        self._create_result(
                            file_path=file_path,
                            key_path=key_path,
                            message=(
                                f"Unknown client-server policy value: "
                                f"'{policy_value}'"
                            ),
                            suggestion=(
                                "Use 'CS_NEG_REQUIRE' for secure connections "
                                "or 'CS_NEG_DONT_CARE' for compatibility"
                            ),
                            line_map=line_map,
                        )
                    )

        return results


class WeakPasswordRule(Rule):
    """Rule to check for weak passwords."""

    def __init__(self):
        super().__init__(
            rule_id="SEC002",
            name="Weak Password Detection",
            description="Check for weak or default passwords",
            severity=Severity.WARNING,
            tags=["security", "password", "authentication"],
        )

    def check(
        self,
        config_data: Dict[str, Any],
        file_path: Path,
        line_map: Dict[str, int] = None,
    ) -> List[LintResult]:
        results = []

        # Common weak passwords
        weak_passwords = {
            "password",
            "123456",
            "admin",
            "root",
            "test",
            "testpassword",
            "irods",
            "rods",
            "changeme",
            "default",
        }

        # Check admin password
        admin_password = config_data.get("admin_password")
        if admin_password and admin_password.lower() in weak_passwords:
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="admin_password",
                    message=f"Weak admin password detected: '{admin_password}'",
                    suggestion=(
                        "Use a strong password with at least 12 characters, "
                        "mixing uppercase, lowercase, numbers, and symbols"
                    ),
                    line_map=line_map,
                )
            )

        # Check database password
        db_config = (
            config_data.get("server_config", {})
            .get("plugin_configuration", {})
            .get("database", {})
        )
        db_password = db_config.get("password")
        if db_password and db_password.lower() in weak_passwords:
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.plugin_configuration.database.password",
                    message=f"Weak database password detected: '{db_password}'",
                    suggestion=(
                        "Use a strong database password with at least " "12 characters"
                    ),
                    line_map=line_map,
                )
            )

        return results


class InsecureKeysRule(Rule):
    """Rule to check for default or weak encryption keys."""

    def __init__(self):
        super().__init__(
            rule_id="SEC003",
            name="Insecure Encryption Keys",
            description="Check for default or weak encryption keys",
            severity=Severity.ERROR,
            tags=["security", "encryption", "keys"],
        )

    def check(
        self,
        config_data: Dict[str, Any],
        file_path: Path,
        line_map: Dict[str, int] = None,
    ) -> List[LintResult]:
        results = []

        server_config = config_data.get("server_config", {})

        # Check zone key
        zone_key = server_config.get("zone_key")
        if zone_key == "TEMPORARY_ZONE_KEY":
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.zone_key",
                    message="Default zone key detected",
                    suggestion=(
                        "Generate a unique zone key with up to 49 "
                        "alphanumeric characters (no hyphens)"
                    ),
                    line_map=line_map,
                )
            )
        elif zone_key and len(zone_key) < 16:
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.zone_key",
                    message=(f"Zone key is too short ({len(zone_key)} characters)"),
                    suggestion=(
                        "Use a zone key with at least 16 characters "
                        "for better security"
                    ),
                    line_map=line_map,
                )
            )

        # Check negotiation key
        negotiation_key = server_config.get("negotiation_key")
        if negotiation_key == "32_byte_server_negotiation_key__":
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.negotiation_key",
                    message="Default negotiation key detected",
                    suggestion="Generate a unique 32-character negotiation key",
                    line_map=line_map,
                )
            )
        elif negotiation_key and len(negotiation_key) != 32:
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.negotiation_key",
                    message=(
                        f"Negotiation key must be exactly 32 characters "
                        f"(current: {len(negotiation_key)})"
                    ),
                    suggestion=(
                        "Generate a negotiation key with exactly 32 "
                        "alphanumeric characters"
                    ),
                    line_map=line_map,
                )
            )

        return results


class DatabaseConfigRule(Rule):
    """Rule to check database configuration."""

    def __init__(self):
        super().__init__(
            rule_id="DB001",
            name="Database Configuration",
            description="Check database configuration for best practices",
            severity=Severity.WARNING,
            tags=["database", "configuration", "performance"],
        )

    def check(
        self,
        config_data: Dict[str, Any],
        file_path: Path,
        line_map: Dict[str, int] = None,
    ) -> List[LintResult]:
        results = []

        db_config = (
            config_data.get("server_config", {})
            .get("plugin_configuration", {})
            .get("database", {})
        )

        if not db_config:
            return results

        # Check for localhost without SSL
        host = db_config.get("host", "")
        if host.lower() in ["localhost", "127.0.0.1"] and not self._has_ssl_config(
            db_config
        ):
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.plugin_configuration.database.host",
                    message=(
                        "Database connection to localhost without SSL " "configuration"
                    ),
                    suggestion=(
                        "Consider configuring SSL for database connections "
                        "even on localhost for defense in depth"
                    ),
                    line_map=line_map,
                )
            )

        # Check for default database names
        db_name = db_config.get("name", "")
        if db_name.lower() in ["icat", "test", "irods_test"]:
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.plugin_configuration.database.name",
                    message=f"Using common database name '{db_name}'",
                    suggestion=(
                        "Consider using a more specific database name "
                        "for better security through obscurity"
                    ),
                    line_map=line_map,
                )
            )

        return results

    def _has_ssl_config(self, db_config: Dict[str, Any]) -> bool:
        """Check if database configuration includes SSL settings."""
        ssl_indicators = ["ssl", "tls", "encrypt", "secure"]
        for key, value in db_config.items():
            if any(indicator in key.lower() for indicator in ssl_indicators):
                return True
        return False


class PortConfigRule(Rule):
    """Rule to check port configuration."""

    def __init__(self):
        super().__init__(
            rule_id="NET001",
            name="Port Configuration",
            description="Check network port configuration for security",
            severity=Severity.INFO,
            tags=["network", "ports", "security"],
        )

    def check(
        self,
        config_data: Dict[str, Any],
        file_path: Path,
        line_map: Dict[str, int] = None,
    ) -> List[LintResult]:
        results = []

        server_config = config_data.get("server_config", {})

        # Check zone port
        zone_port = server_config.get("zone_port")
        if zone_port == 1247:  # Default port
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.zone_port",
                    message="Using default iRODS port (1247)",
                    suggestion=(
                        "Consider using a non-standard port for " "additional security"
                    ),
                    line_map=line_map,
                )
            )

        # Check port range
        start_port = server_config.get("server_port_range_start")
        end_port = server_config.get("server_port_range_end")

        if start_port and end_port:
            port_range = end_port - start_port
            if port_range > 1000:
                results.append(
                    self._create_result(
                        file_path=file_path,
                        key_path="server_config.server_port_range_start",
                        message=(f"Large port range configured ({port_range} ports)"),
                        suggestion=(
                            "Consider using a smaller port range to "
                            "reduce attack surface"
                        ),
                        line_map=line_map,
                    )
                )

        return results


class FilePermissionsRule(Rule):
    """Rule to check file and directory permissions."""

    def __init__(self):
        super().__init__(
            rule_id="FS001",
            name="File Permissions",
            description="Check file and directory permissions for security",
            severity=Severity.WARNING,
            tags=["filesystem", "permissions", "security"],
        )

    def check(
        self,
        config_data: Dict[str, Any],
        file_path: Path,
        line_map: Dict[str, int] = None,
    ) -> List[LintResult]:
        results = []

        server_config = config_data.get("server_config", {})

        # Check default file mode
        file_mode = server_config.get("default_file_mode")
        if file_mode and file_mode == "0644":
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.default_file_mode",
                    message="Default file mode allows world-readable files",
                    suggestion="Consider using '0600' or '0640' for better security",
                    line_map=line_map,
                )
            )

        # Check default directory mode
        dir_mode = server_config.get("default_dir_mode")
        if dir_mode and dir_mode == "0755":
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.default_dir_mode",
                    message="Default directory mode allows world access",
                    suggestion="Consider using '0750' or '0700' for better security",
                    line_map=line_map,
                )
            )

        return results


class JsonRule(Rule):
    """A rule loaded from JSON configuration."""

    def __init__(self, rule_data: Dict[str, Any]):
        """Initialize rule from JSON data."""
        # Normalize severity to lowercase to match enum values
        severity_str = rule_data["severity"].lower()

        super().__init__(
            rule_id=rule_data["id"],
            name=rule_data["name"],
            description=rule_data["description"],
            severity=Severity(severity_str),
            tags=rule_data.get("tags", []),
            documentation_url=rule_data.get("documentation_url"),
        )
        self.rule_type = rule_data["type"]
        self.config = rule_data.get("config", {})
        self.enabled = rule_data.get("enabled", True)

    def check(
        self,
        config_data: Dict[str, Any],
        file_path: Path,
        line_map: Dict[str, int] = None,
    ) -> List[LintResult]:
        """Check the configuration based on rule type."""
        if self.rule_type == "security_policy":
            return self._check_security_policy(config_data, file_path, line_map)
        elif self.rule_type == "weak_password":
            return self._check_weak_password(config_data, file_path, line_map)
        elif self.rule_type == "insecure_keys":
            return self._check_insecure_keys(config_data, file_path, line_map)
        elif self.rule_type == "database_config":
            return self._check_database_config(config_data, file_path, line_map)
        elif self.rule_type == "port_config":
            return self._check_port_config(config_data, file_path, line_map)
        elif self.rule_type == "file_permissions":
            return self._check_file_permissions(config_data, file_path, line_map)
        elif self.rule_type == "version_specific":
            return self._check_version_specific(config_data, file_path, line_map)
        else:
            return []

    def _check_security_policy(
        self, config_data: Dict[str, Any], file_path: Path, line_map: Dict[str, int]
    ) -> List[LintResult]:
        """Check client-server security policy."""
        results = []
        check_locations = self.config.get("check_locations", [])
        forbidden_values = self.config.get("forbidden_values", [])
        allowed_values = self.config.get("allowed_values", [])

        for location in check_locations:
            value = self._get_nested_value(config_data, location)
            if value is not None:
                if value in forbidden_values:
                    results.append(
                        self._create_result(
                            file_path=file_path,
                            key_path=location,
                            message=(
                                f"Client-server policy is set to '{value}' "
                                "which may allow insecure connections"
                            ),
                            suggestion=(
                                f"Change to one of: {', '.join(allowed_values)} "
                                "for better security"
                            ),
                            line_map=line_map,
                        )
                    )
                elif allowed_values and value not in allowed_values:
                    results.append(
                        self._create_result(
                            file_path=file_path,
                            key_path=location,
                            message=f"Unknown client-server policy value: '{value}'",
                            suggestion=(f"Use one of: {', '.join(allowed_values)}"),
                            line_map=line_map,
                        )
                    )

        return results

    def _check_weak_password(
        self, config_data: Dict[str, Any], file_path: Path, line_map: Dict[str, int]
    ) -> List[LintResult]:
        """Check for weak passwords."""
        results = []
        weak_passwords = set(p.lower() for p in self.config.get("weak_passwords", []))
        min_length = self.config.get("min_length", 8)
        check_fields = self.config.get("check_fields", [])

        for field_path in check_fields:
            password = self._get_nested_value(config_data, field_path)
            if password:
                if password.lower() in weak_passwords:
                    results.append(
                        self._create_result(
                            file_path=file_path,
                            key_path=field_path,
                            message=f"Weak password detected: '{password}'",
                            suggestion=(
                                f"Use a strong password with at least "
                                f"{min_length} characters"
                            ),
                            line_map=line_map,
                        )
                    )
                elif len(password) < min_length:
                    results.append(
                        self._create_result(
                            file_path=file_path,
                            key_path=field_path,
                            message=(
                                f"Password too short: {len(password)} characters "
                                f"(minimum: {min_length})"
                            ),
                            suggestion=(
                                f"Use a password with at least {min_length} "
                                "characters"
                            ),
                            line_map=line_map,
                        )
                    )

        return results

    def _check_insecure_keys(
        self, config_data: Dict[str, Any], file_path: Path, line_map: Dict[str, int]
    ) -> List[LintResult]:
        """Check for insecure encryption keys."""
        results = []
        server_config = config_data.get("server_config", {})

        # Check zone key
        zone_config = self.config.get("zone_key", {})
        zone_key = server_config.get("zone_key")
        if zone_key:
            default_value = zone_config.get("default_value")
            min_length = zone_config.get("min_length", 16)

            if zone_key == default_value:
                results.append(
                    self._create_result(
                        file_path=file_path,
                        key_path="server_config.zone_key",
                        message="Default zone key detected",
                        suggestion="Generate a unique zone key",
                        line_map=line_map,
                    )
                )
            elif len(zone_key) < min_length:
                results.append(
                    self._create_result(
                        file_path=file_path,
                        key_path="server_config.zone_key",
                        message=(
                            f"Zone key too short: {len(zone_key)} characters "
                            f"(minimum: {min_length})"
                        ),
                        suggestion=f"Use at least {min_length} characters",
                        line_map=line_map,
                    )
                )

        # Check negotiation key
        neg_config = self.config.get("negotiation_key", {})
        neg_key = server_config.get("negotiation_key")
        if neg_key:
            default_value = neg_config.get("default_value")
            required_length = neg_config.get("required_length", 32)

            if neg_key == default_value:
                results.append(
                    self._create_result(
                        file_path=file_path,
                        key_path="server_config.negotiation_key",
                        message="Default negotiation key detected",
                        suggestion=f"Generate a unique {required_length}-character key",
                        line_map=line_map,
                    )
                )
            elif len(neg_key) != required_length:
                results.append(
                    self._create_result(
                        file_path=file_path,
                        key_path="server_config.negotiation_key",
                        message=(
                            f"Negotiation key must be exactly {required_length} "
                            f"characters (current: {len(neg_key)})"
                        ),
                        suggestion=f"Use exactly {required_length} characters",
                        line_map=line_map,
                    )
                )

        return results

    def _check_database_config(
        self, config_data: Dict[str, Any], file_path: Path, line_map: Dict[str, int]
    ) -> List[LintResult]:
        """Check database configuration."""
        results = []
        db_config = (
            config_data.get("server_config", {})
            .get("plugin_configuration", {})
            .get("database", {})
        )

        if not db_config:
            return results

        ssl_indicators = self.config.get("ssl_indicators", [])
        common_db_names = self.config.get("common_db_names", [])
        localhost_variants = self.config.get("localhost_variants", [])
        require_ssl = self.config.get("require_ssl", False)

        # Check for localhost without SSL
        host = db_config.get("host", "")
        if host.lower() in localhost_variants:
            has_ssl = any(
                indicator in key.lower()
                for key in db_config.keys()
                for indicator in ssl_indicators
            )
            if require_ssl and not has_ssl:
                results.append(
                    self._create_result(
                        file_path=file_path,
                        key_path="server_config.plugin_configuration.database.host",
                        message="Database connection requires SSL configuration",
                        suggestion="Configure SSL for database connections",
                        line_map=line_map,
                    )
                )

        # Check for common database names
        db_name = db_config.get("name", "")
        if db_name.lower() in [name.lower() for name in common_db_names]:
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.plugin_configuration.database.name",
                    message=f"Using common database name '{db_name}'",
                    suggestion="Consider using a more specific database name",
                    line_map=line_map,
                )
            )

        return results

    def _check_port_config(
        self, config_data: Dict[str, Any], file_path: Path, line_map: Dict[str, int]
    ) -> List[LintResult]:
        """Check port configuration."""
        results = []
        server_config = config_data.get("server_config", {})
        default_port = self.config.get("default_port", 1247)
        max_port_range = self.config.get("max_port_range", 1000)

        # Check zone port
        zone_port = server_config.get("zone_port")
        if zone_port == default_port:
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.zone_port",
                    message=f"Using default iRODS port ({default_port})",
                    suggestion="Consider using a non-standard port",
                    line_map=line_map,
                )
            )

        # Check port range
        start_port = server_config.get("server_port_range_start")
        end_port = server_config.get("server_port_range_end")

        if start_port and end_port:
            port_range = end_port - start_port
            if port_range > max_port_range:
                results.append(
                    self._create_result(
                        file_path=file_path,
                        key_path="server_config.server_port_range_start",
                        message=f"Large port range: {port_range} ports",
                        suggestion=f"Consider using less than {max_port_range} ports",
                        line_map=line_map,
                    )
                )

        return results

    def _check_file_permissions(
        self, config_data: Dict[str, Any], file_path: Path, line_map: Dict[str, int]
    ) -> List[LintResult]:
        """Check file permissions."""
        results = []
        server_config = config_data.get("server_config", {})
        insecure_file_modes = self.config.get("insecure_file_modes", [])
        insecure_dir_modes = self.config.get("insecure_dir_modes", [])

        # Check default file mode
        file_mode = server_config.get("default_file_mode")
        if file_mode in insecure_file_modes:
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.default_file_mode",
                    message=f"Insecure file mode: {file_mode}",
                    suggestion="Use more restrictive file permissions",
                    line_map=line_map,
                )
            )

        # Check default directory mode
        dir_mode = server_config.get("default_dir_mode")
        if dir_mode in insecure_dir_modes:
            results.append(
                self._create_result(
                    file_path=file_path,
                    key_path="server_config.default_dir_mode",
                    message=f"Insecure directory mode: {dir_mode}",
                    suggestion="Use more restrictive directory permissions",
                    line_map=line_map,
                )
            )

        return results

    def _check_version_specific(
        self, config_data: Dict[str, Any], file_path: Path, line_map: Dict[str, int]
    ) -> List[LintResult]:
        """Check version-specific configurations."""
        results = []

        # This is a placeholder for version-specific checks
        # Each rule can define its own logic here
        check_paths = self.config.get("check_paths", [])

        for path in check_paths:
            value = self._get_nested_value(config_data, path)
            if value is None:
                results.append(
                    self._create_result(
                        file_path=file_path,
                        key_path=path,
                        message=f"Missing configuration: {path}",
                        suggestion="Configure this setting for your iRODS version",
                        line_map=line_map,
                    )
                )

        return results

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


class RuleEngine:
    """Engine that applies version-specific rules to configuration data."""

    def __init__(
        self, irods_version: Optional[str] = None, rules_dir: Optional[Path] = None
    ):
        self.rule_loader = RuleLoader(rules_dir)
        self.excluded_rules: set[str] = set()
        self.only_rules_set: Optional[set[str]] = None
        self.security_context = SecurityContext.strict()
        self.irods_version = irods_version
        self.current_version: Optional[str] = None
        self.rules: List[JsonRule] = []

    def load_rules_for_version(self, version: str):
        """Load rules for a specific iRODS version."""
        self.current_version = version
        self.rules = self.rule_loader.load_rules(version)

    def load_rules_for_config(
        self, config_data: Dict[str, Any], version_override: Optional[str] = None
    ):
        """Load appropriate rules for a configuration."""
        version = version_override or self._detect_version_from_config(config_data)
        if version:
            self.load_rules_for_version(version)
        else:
            # Fallback to latest version if detection fails
            self.load_rules_for_version("5.0.x")

    def _detect_version_from_config(self, config_data: Dict[str, Any]) -> Optional[str]:
        """Detect iRODS version from configuration data."""
        return self.rule_loader.detect_version_from_config(config_data)

    def exclude_rules(self, rule_ids: List[str]):
        """Exclude specific rules from execution."""
        self.excluded_rules.update(rule_ids)

    def only_rules(self, rule_ids: List[str]):
        """Only run specific rules."""
        self.only_rules_set = set(rule_ids)

    def apply_rules(
        self, config_data: Dict[str, Any], file_path: Path
    ) -> List[LintResult]:
        """Apply all enabled rules to the configuration data."""
        # Load rules if not already loaded
        if not self.rules:
            if self.irods_version:
                # Use explicit version if provided
                self.load_rules_for_version(self.irods_version)
            else:
                # Auto-detect version from config
                self.load_rules_for_config(config_data)

        results = []
        metadata = config_data.get("_metadata", {})
        line_map = metadata.get("line_map", {})

        for rule in self.rules:
            # Skip disabled rules
            if not rule.enabled:
                continue

            # Skip excluded rules
            if rule.rule_id in self.excluded_rules:
                continue

            # If only_rules is set, skip rules not in the list
            if self.only_rules_set and rule.rule_id not in self.only_rules_set:
                continue

            try:
                rule_results = rule.check(config_data, file_path, line_map)
                results.extend(rule_results)
            except Exception as e:
                # Log error but continue with other rules
                error_result = LintResult(
                    file_path=file_path,
                    line_number=1,
                    column=None,
                    severity=Severity.ERROR,
                    rule_id="RULE_ERROR",
                    message=f"Error executing rule {rule.rule_id}: {e}",
                    suggestion="Check rule implementation or configuration format",
                )
                results.append(error_result)

        return results

    def get_available_versions(self) -> List[str]:
        """Get list of available iRODS versions."""
        return self.rule_loader.get_available_versions()

    def get_rule_info(self) -> List[Dict[str, Any]]:
        """Get information about all loaded rules."""
        return [
            {
                "id": rule.rule_id,
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity.value,
                "tags": rule.tags,
                "enabled": rule.enabled,
                "documentation_url": rule.documentation_url,
                "type": rule.rule_type,
                "version": self.current_version,
            }
            for rule in self.rules
        ]

    def validate_all_rule_files(self) -> Dict[str, List[str]]:
        """Validate all rule files."""
        validation_results = {}

        for version in self.rule_loader.get_available_versions():
            rule_file = self.rule_loader.rules_dir / f"{version}.json"
            errors = self.rule_loader.validate_rule_file(rule_file)
            if errors:
                validation_results[version] = errors

        return validation_results
