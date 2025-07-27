#!/usr/bin/env python3

from pathlib import Path

from setuptools import find_packages, setup

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="irods-linter",
    version="1.0.0",
    author="iRODS Linter Team",
    author_email="metadata-school@example.com",
    description=(
        "A linter for iRODS configuration files that checks for "
        "best practices and security issues"
    ),
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/metadata-school/irods_linter",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: System :: Systems Administration",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "rich>=13.0.0",
        "python-dotenv>=1.0.0",
        "jsonschema>=4.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "irods-linter=irods_linter:main",
        ],
    },
    include_package_data=True,
    package_data={
        "linter": ["schemas/*.json", "rules/*.yaml"],
    },
)
