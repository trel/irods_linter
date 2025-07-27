#!/usr/bin/env python3
"""
Test script to demonstrate iRODS linter capabilities.

This script runs various test scenarios to show how the linter works.
"""

import subprocess
import sys
from pathlib import Path


def run_command(cmd):
    """Run a command and return the result."""
    print(f"\n{'='*60}")
    print(f"Running: {' '.join(cmd)}")
    print("=" * 60)

    result = subprocess.run(cmd, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)

    return result.returncode


def main():
    """Run demonstration tests."""
    base_dir = Path(__file__).parent
    linter_script = base_dir / "irods_linter.py"
    python_exe = base_dir / ".venv" / "bin" / "python"

    sample_file = base_dir / "examples" / "sample_unattended_installation.json"
    secure_file = base_dir / "examples" / "secure_unattended_installation.json"

    print("iRODS Configuration Linter - Demonstration")
    print("==========================================")

    # Test 1: Basic linting with issues
    print("\n1. Testing with problematic configuration:")
    run_command([str(python_exe), str(linter_script), str(sample_file)])

    # Test 2: Table format
    print("\n2. Testing table output format:")
    run_command(
        [str(python_exe), str(linter_script), "--format", "table", str(sample_file)]
    )

    # Test 3: Secure configuration (should pass)
    print("\n3. Testing secure configuration:")
    run_command([str(python_exe), str(linter_script), str(secure_file)])

    # Test 4: Filter by severity
    print("\n4. Testing severity filtering (errors only):")
    run_command(
        [str(python_exe), str(linter_script), "--severity", "error", str(sample_file)]
    )

    # Test 5: Exclude rules
    print("\n5. Testing rule exclusion (exclude password checks):")
    run_command(
        [
            str(python_exe),
            str(linter_script),
            "--exclude-rules",
            "SEC002",
            "--",
            str(sample_file),
        ]
    )

    # Test 6: JSON output
    print("\n6. Testing JSON output format:")
    result = run_command(
        [
            str(python_exe),
            str(linter_script),
            "--format",
            "json",
            "--severity",
            "error",
            str(sample_file),
        ]
    )

    print("\n" + "=" * 60)
    print("Demonstration complete!")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
