"""
Data models for the iRODS linter.

This module contains the core data structures used throughout the linter,
including result objects and enums.
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional


class Severity(Enum):
    """Severity levels for lint results."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    STYLE = "style"


class ConfigType(Enum):
    """Types of iRODS configuration files."""

    UNATTENDED_INSTALLATION = "unattended_installation"
    SERVER_CONFIG = "server_config"
    SERVICE_ACCOUNT_ENVIRONMENT = "service_account_environment"
    IRODS_ENVIRONMENT = "irods_environment"
    UNKNOWN = "unknown"


@dataclass
class LintResult:
    """Represents a single linting result."""

    file_path: Path
    line_number: int
    column: Optional[int]
    severity: Severity
    rule_id: str
    message: str
    suggestion: Optional[str] = None
    documentation_url: Optional[str] = None

    def __str__(self) -> str:
        location = f"line {self.line_number}"
        if self.column:
            location += f", column {self.column}"
        return f"{self.file_path}:{location}: {self.severity.value}: {self.rule_id}: {self.message}"


@dataclass
class ConfigSection:
    """Represents a section of configuration with metadata."""

    name: str
    data: Any
    line_number: int
    source_file: Path
    parent_section: Optional[str] = None


@dataclass
class RuleDefinition:
    """Defines a linting rule."""

    id: str
    name: str
    description: str
    severity: Severity
    tags: list[str]
    enabled: bool = True
    documentation_url: Optional[str] = None

    def __post_init__(self):
        """Validate rule definition after initialization."""
        if not self.id:
            raise ValueError("Rule ID cannot be empty")
        if not self.name:
            raise ValueError("Rule name cannot be empty")


@dataclass
class LinterConfig:
    """Configuration for the linter itself."""

    enabled_rules: set[str]
    disabled_rules: set[str]
    severity_overrides: Dict[str, Severity]
    custom_rules_dirs: list[Path]

    @classmethod
    def default(cls) -> "LinterConfig":
        """Create default linter configuration."""
        return cls(
            enabled_rules=set(),
            disabled_rules=set(),
            severity_overrides={},
            custom_rules_dirs=[],
        )


@dataclass
class SecurityContext:
    """Context for security-related rules."""

    requires_ssl: bool = True
    allows_plaintext_passwords: bool = False
    requires_strong_keys: bool = True
    minimum_key_length: int = 32

    @classmethod
    def strict(cls) -> "SecurityContext":
        """Create strict security context."""
        return cls(
            requires_ssl=True,
            allows_plaintext_passwords=False,
            requires_strong_keys=True,
            minimum_key_length=32,
        )

    @classmethod
    def permissive(cls) -> "SecurityContext":
        """Create permissive security context."""
        return cls(
            requires_ssl=False,
            allows_plaintext_passwords=True,
            requires_strong_keys=False,
            minimum_key_length=16,
        )
