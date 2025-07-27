# iRODS Configuration Linter

A comprehensive linting tool for iRODS configuration files that helps ensure best practices and security compliance. Similar to `shellcheck` for shell scripts, this tool analyzes iRODS configuration files and provides actionable feedback.

## Features

- 🔍 **Comprehensive Analysis**: Checks multiple types of iRODS configuration files
- 🛡️ **Security Focus**: Identifies security misconfigurations and vulnerabilities
- 📋 **Multiple Output Formats**: Default, table, and JSON output formats
- 🎯 **Rule-based**: Easily extensible rule system for custom checks
- 🔧 **Configurable**: Fine-tune which rules to run and their severity levels
- 📚 **Rich Documentation**: Detailed explanations and suggestions for each issue

## Supported Configuration Files

- Unattended installation files
- Server configuration (`server_config.json`)
- Service account environment (`irods_environment.json`)
- Client environment files

## Installation

### From Source

```bash
git clone https://github.com/metadata-school/irods_linter.git
cd irods_linter
pip install -r requirements.txt
```

### Using pip (when published)

```bash
pip install irods-linter
```

## Quick Start

### Basic Usage

```bash
# Lint a single configuration file
python irods_linter.py config.json

# Lint multiple files
python irods_linter.py *.json

# Specify iRODS version for version-specific rules
python irods_linter.py --irods-version 5.0.1 config.json

# Output as table
python irods_linter.py --format table config.json

# Output as JSON
python irods_linter.py --format json config.json
```

### Example Output

```
In examples/sample_unattended_installation.json:

error: line 10
  SEC001: Client-server policy is set to 'CS_NEG_REFUSE' which allows unencrypted connections
  Suggestion: Change to 'CS_NEG_REQUIRE' to enforce SSL/TLS encryption for all connections

warning: line 1
  SEC002: Weak admin password detected: 'rods'
  Suggestion: Use a strong password with at least 12 characters, mixing uppercase, lowercase, numbers, and symbols

error: line 45
  SEC003: Default zone key detected
  Suggestion: Generate a unique zone key with up to 49 alphanumeric characters (no hyphens)
```

## Rules

### Security Rules

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| SEC001 | Secure Client-Server Policy | Checks that SSL/TLS is required for client-server communication | ERROR |
| SEC002 | Weak Password Detection | Identifies weak or default passwords | WARNING |
| SEC003 | Insecure Encryption Keys | Detects default or weak encryption keys | ERROR |

### Database Rules

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| DB001 | Database Configuration | Checks database configuration best practices | WARNING |

### Network Rules

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| NET001 | Port Configuration | Validates network port configuration | INFO |

### Filesystem Rules

| Rule ID | Name | Description | Severity |
|---------|------|-------------|----------|
| FS001 | File Permissions | Checks file and directory permissions | WARNING |

## Version-Dependent Rules

The linter supports version-specific rules that reflect the evolution of iRODS security requirements and capabilities across different versions.

### Supported Versions

- **4.0.x**: Basic security checks with lenient policies
- **4.1.x**: Enhanced password requirements  
- **4.2.x**: Stricter SSL policies and enhanced database checks
- **4.3.x**: Improved key validation
- **5.0.x**: Advanced security features and strict SSL requirements

### Version Differences Example

The same configuration may receive different severities based on iRODS version:

**SSL Policy (CS_NEG_REFUSE)**:
- 4.0.x: **WARNING** (basic SSL support)
- 4.2.x+: **ERROR** (enhanced SSL support)
- 5.0.x: **ERROR** with stricter allowed values

**Password Requirements**:
- 4.0.x: 6+ characters minimum
- 4.1.x: 10+ characters minimum  
- 4.2.x+: 12+ characters minimum

### Usage

```bash
# Automatically detect version from config (if possible)
python irods_linter.py config.json

# Specify version explicitly
python irods_linter.py --irods-version 5.0.1 config.json
python irods_linter.py --irods-version 4.2.8 config.json
```

## Configuration

### Environment Variables

Create a `.env` file in your project directory:

```bash
# Custom rules directory
IRODS_LINTER_RULES_DIR=/path/to/custom/rules

# Default severity level
IRODS_LINTER_DEFAULT_SEVERITY=warning

# Enable/disable specific rule categories
IRODS_LINTER_ENABLE_SECURITY=true
IRODS_LINTER_ENABLE_PERFORMANCE=true
```

### Command Line Options

```bash
python irods_linter.py --help
```

#### Key Options

- `--irods-version`: Specify iRODS version for version-specific rules (e.g., 4.2.8, 5.0.1)
- `--format`: Output format (default, table, json)
- `--severity`: Minimum severity level to show (error, warning, info, style)
- `--exclude-rules`: Rule IDs to exclude
- `--only-rules`: Only run specified rules
- `--verbose`: Verbose output

## Example Configurations

### Secure Configuration

```json
{
    "service_account_environment": {
        "irods_client_server_policy": "CS_NEG_REQUIRE"
    },
    "server_config": {
        "client_server_policy": "CS_NEG_REQUIRE",
        "zone_key": "my_unique_zone_key_with_49_chars_max_length_123",
        "negotiation_key": "unique_32_character_negotiation_key_here",
        "default_file_mode": "0600",
        "default_dir_mode": "0750"
    }
}
```

## Adding Custom Rules

### Creating a Custom Rule

```python
from linter.rules import Rule
from linter.models import LintResult, Severity

class CustomRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="CUSTOM001",
            name="Custom Check",
            description="My custom security check",
            severity=Severity.WARNING,
            tags=["custom", "security"]
        )
    
    def check(self, config_data, file_path, line_map=None):
        results = []
        # Your custom logic here
        return results
```

### Rule Development Guidelines

1. **Unique IDs**: Use a consistent prefix (e.g., SEC, DB, NET)
2. **Clear Messages**: Provide actionable error messages
3. **Helpful Suggestions**: Always include suggestions for fixes
4. **Appropriate Severity**: Choose the right severity level
5. **Documentation**: Include documentation URLs when available

## Integration

### CI/CD Integration

```yaml
# GitHub Actions example
name: iRODS Config Lint
on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.11'
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    - name: Lint iRODS configs
      run: |
        python irods_linter.py configs/*.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: irods-linter
        name: iRODS Configuration Linter
        entry: python irods_linter.py
        language: python
        files: \.json$
        args: [--format=default]
```

## Development

### Running Tests

The project includes a comprehensive test suite with high coverage:

```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
make test

# Run tests with coverage report
make test-cov

# Run quick tests (fail fast)
make test-quick
```

**Test Coverage**: The test suite achieves >90% code coverage and includes:
- Unit tests for all rule types
- Integration tests for CLI functionality
- Configuration parser tests
- Model validation tests
- End-to-end workflow tests

### Code Quality

This project uses multiple tools to maintain high code quality:

```bash
# Format code
make format

# Run linting checks  
make lint-code

# Run all CI checks locally
make ci
```

### Pre-commit Hooks

Install pre-commit hooks to automatically run checks before commits:

```bash
# Install pre-commit hooks
make pre-commit-install

# Run pre-commit on all files
make pre-commit-run
```

The pre-commit hooks include:
- **Black**: Code formatting
- **isort**: Import sorting  
- **flake8**: Code linting and style checks
- **mypy**: Type checking
- **bandit**: Security vulnerability scanning
- **JSON formatting**: Pretty-print JSON files
- **Markdown linting**: Documentation quality
- **Test execution**: Ensure tests pass

## Common Issues and Solutions

### Issue: "CS_NEG_REFUSE" Policy

**Problem**: Client-server policy allows unencrypted connections

**Solution**: Change to `CS_NEG_REQUIRE`:
```json
{
    "irods_client_server_policy": "CS_NEG_REQUIRE"
}
```

### Issue: Default Encryption Keys

**Problem**: Using default zone or negotiation keys

**Solution**: Generate unique keys:
```bash
# Zone key (up to 49 alphanumeric characters)
openssl rand -hex 24 | cut -c1-49

# Negotiation key (exactly 32 characters)
openssl rand -hex 16
```

### Issue: Weak Passwords

**Problem**: Using default or weak passwords

**Solution**: Use strong passwords:
```bash
# Generate a strong password
openssl rand -base64 32
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Contribution Guidelines

- Add tests for new rules
- Update documentation
- Follow the existing code style
- Ensure all rules have appropriate severity levels
- Include examples in rule documentation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by [shellcheck](https://www.shellcheck.net/)
- Built for the iRODS community
- Uses the excellent [Rich](https://github.com/Textualize/rich) library for terminal output

## Support

- 📖 [Documentation](https://github.com/metadata-school/irods_linter/wiki)
- 🐛 [Issue Tracker](https://github.com/metadata-school/irods_linter/issues)
- 💬 [Discussions](https://github.com/metadata-school/irods_linter/discussions)
A linter for iRODS configfuration files
