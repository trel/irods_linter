#!/usr/bin/env python3
"""
iRODS Configuration Linter

A tool that analyzes iRODS configuration files and provides feedback on
best practices, similar to shellcheck for shell scripts.

Author: iRODS Linter Team
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from linter.config_parser import ConfigParser
from linter.models import LintResult, Severity
from linter.rules import RuleEngine


class IRODSLinter:
    """Main linter class that orchestrates the linting process."""

    def __init__(self, console: Console, irods_version: Optional[str] = None):
        self.console = console
        self.config_parser = ConfigParser()
        self.rule_engine = RuleEngine(irods_version)

    def get_available_versions(self) -> List[str]:
        """Return list of available iRODS versions."""
        return self.rule_engine.rule_loader.get_available_versions()

    def lint_configs(
        self, config_paths: List[Path], only_rules: Optional[List[str]] = None
    ):
        """Lint configuration files."""
        all_results = []
        for config_path in config_paths:
            results = self.lint_file(config_path, only_rules)
            all_results.extend(results)
        return all_results

    def lint_file(self, file_path: Path, only_rules: Optional[List[str]] = None):
        """Lint a single configuration file."""
        try:
            config_data = self.config_parser.parse_file(file_path)

            # Apply rules using the configured version
            return self.rule_engine.apply_rules(config_data, file_path)
        except Exception as e:
            return [
                LintResult(
                    file_path=file_path,
                    line_number=1,
                    column=1,
                    severity=Severity.ERROR,
                    rule_id="PARSE_ERROR",
                    message=f"Failed to parse configuration file: {e}",
                    suggestion="Check file format and syntax",
                )
            ]

    def set_irods_version(self, version: str):
        """Set the iRODS version for linting."""
        self.irods_version = version

    def display_results(self, results: List[LintResult], format_type: str = "default"):
        """Display linting results in various formats."""
        if format_type == "json":
            self._display_json(results)
        elif format_type == "table":
            self._display_table(results)
        else:
            self._display_default(results)

    def _display_default(self, results: List[LintResult]):
        """Display results in shellcheck-like format."""
        if not results:
            self.console.print("[green]✓[/green] No issues found!")
            return

        # Group by file
        files = {}
        for result in results:
            if result.file_path not in files:
                files[result.file_path] = []
            files[result.file_path].append(result)

        for file_path, file_results in files.items():
            self.console.print(f"\n[bold]In {file_path}:[/bold]")

            for result in file_results:
                # Color based on severity
                color = {
                    Severity.ERROR: "red",
                    Severity.WARNING: "yellow",
                    Severity.INFO: "blue",
                    Severity.STYLE: "cyan",
                }.get(result.severity, "white")

                # Format like shellcheck
                location = f"line {result.line_number}"
                if result.column:
                    location += f", column {result.column}"

                self.console.print(
                    f"[{color}]{result.severity.value}[/{color}]: {location}"
                )
                self.console.print(
                    f"  [{color}]{result.rule_id}[/{color}]: {result.message}"
                )

                if result.suggestion:
                    self.console.print(f"  [dim]Suggestion: {result.suggestion}[/dim]")

                if result.documentation_url:
                    self.console.print(
                        f"  [dim]Documentation: {result.documentation_url}[/dim]"
                    )

                self.console.print()

    def _display_table(self, results: List[LintResult]):
        """Display results in a table format."""
        if not results:
            self.console.print("[green]✓[/green] No issues found!")
            return

        table = Table(title="iRODS Configuration Lint Results")
        table.add_column("File", style="cyan")
        table.add_column("Line", justify="right")
        table.add_column("Severity", justify="center")
        table.add_column("Rule", style="magenta")
        table.add_column("Message", style="white")

        for result in results:
            severity_style = {
                Severity.ERROR: "[red]ERROR[/red]",
                Severity.WARNING: "[yellow]WARNING[/yellow]",
                Severity.INFO: "[blue]INFO[/blue]",
                Severity.STYLE: "[cyan]STYLE[/cyan]",
            }.get(result.severity, "UNKNOWN")

            table.add_row(
                str(result.file_path.name),
                str(result.line_number),
                severity_style,
                result.rule_id,
                result.message,
            )

        self.console.print(table)

    def _display_json(self, results: List[LintResult]):
        """Display results in JSON format."""
        json_results = []
        for result in results:
            json_results.append(
                {
                    "file": str(result.file_path),
                    "line": result.line_number,
                    "column": result.column,
                    "severity": result.severity.value,
                    "rule_id": result.rule_id,
                    "message": result.message,
                    "suggestion": result.suggestion,
                    "documentation_url": result.documentation_url,
                }
            )

        self.console.print_json(data=json_results)


def main():
    """Main entry point for the CLI."""
    # Load environment variables
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Lint iRODS configuration files for best practices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  irods_linter config.json                    # Lint single file
  irods_linter *.json                         # Lint multiple files
  irods_linter --format table config.json    # Display as table
  irods_linter --format json config.json     # Output as JSON
  irods_linter --rules-dir ./custom config.json  # Use custom rules
        """,
    )

    parser.add_argument(
        "files", nargs="*", type=Path, help="Configuration files to lint"
    )

    parser.add_argument(
        "--format",
        choices=["default", "table", "json"],
        default="default",
        help="Output format (default: %(default)s)",
    )

    parser.add_argument(
        "--severity",
        choices=["error", "warning", "info", "style"],
        default="info",
        help="Minimum severity level to show (default: %(default)s)",
    )

    parser.add_argument(
        "--rules-dir", type=Path, help="Directory containing custom rule definitions"
    )

    parser.add_argument(
        "--exclude-rules", nargs="*", help="Rule IDs to exclude from linting"
    )

    parser.add_argument("--only-rules", nargs="*", help="Only run specified rule IDs")

    parser.add_argument("--config", type=Path, help="Path to linter configuration file")

    parser.add_argument(
        "--irods-version",
        help="Specify iRODS version for rule selection (e.g., 4.3.x, 5.0.x)",
    )

    parser.add_argument(
        "--list-versions",
        action="store_true",
        help="List available iRODS versions and exit",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    parser.add_argument("--version", action="version", version="iRODS Linter 1.0.0")

    args = parser.parse_args()

    console = Console()

    # Handle list-versions command
    if args.list_versions:
        linter = IRODSLinter(console)
        versions = linter.get_available_versions()
        console.print("[bold cyan]Available iRODS Versions:[/bold cyan]")
        for version in versions:
            console.print(f"  • {version}")
        sys.exit(0)

    # Require files if not using --list-versions
    if not args.files:
        parser.error("the following arguments are required: files")

    linter = IRODSLinter(console, args.irods_version)

    # Configure rule engine based on arguments
    if args.rules_dir:
        linter.rule_engine.load_custom_rules(args.rules_dir)

    if args.exclude_rules:
        linter.rule_engine.exclude_rules(args.exclude_rules)

    if args.only_rules:
        linter.rule_engine.only_rules(args.only_rules)

    # Process files
    all_results = []
    error_count = 0

    for file_path in args.files:
        if not file_path.exists():
            console.print(f"[red]Error:[/red] File not found: {file_path}")
            error_count += 1
            continue

        if args.verbose:
            console.print(f"[dim]Linting {file_path}...[/dim]")

        results = linter.lint_file(file_path)

        # Filter by severity
        severity_levels = {
            "error": [Severity.ERROR],
            "warning": [Severity.ERROR, Severity.WARNING],
            "info": [Severity.ERROR, Severity.WARNING, Severity.INFO],
            "style": [Severity.ERROR, Severity.WARNING, Severity.INFO, Severity.STYLE],
        }

        filtered_results = [
            r for r in results if r.severity in severity_levels[args.severity]
        ]

        all_results.extend(filtered_results)

        # Count errors for exit code
        error_count += len(
            [r for r in filtered_results if r.severity == Severity.ERROR]
        )

    # Display results
    linter.display_results(all_results, args.format)

    # Summary
    if all_results and args.format == "default":
        total_issues = len(all_results)
        errors = len([r for r in all_results if r.severity == Severity.ERROR])
        warnings = len([r for r in all_results if r.severity == Severity.WARNING])

        console.print(f"\n[bold]Summary:[/bold] {total_issues} issue(s) found")
        if errors:
            console.print(f"  [red]Errors:[/red] {errors}")
        if warnings:
            console.print(f"  [yellow]Warnings:[/yellow] {warnings}")

    # Exit with error code if there were errors
    sys.exit(1 if error_count > 0 else 0)


if __name__ == "__main__":
    main()
