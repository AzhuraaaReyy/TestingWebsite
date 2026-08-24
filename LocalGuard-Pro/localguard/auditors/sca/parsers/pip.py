"""Python dependencies parser for LocalGuard-Pro SCA."""

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import toml

logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    """Represents a parsed dependency."""

    name: str
    version: str
    ecosystem: str
    dev: bool = False
    license: str | None = None
    description: str | None = None
    source: str | None = None


class PipParser:
    """Parser for Python dependency files (requirements.txt, pyproject.toml, poetry.lock)."""

    def __init__(self):
        self.name = "pip"

    def parse(self, dep_file: Path) -> list[Dependency]:
        """Parse Python dependency file."""
        if dep_file.name == "requirements.txt":
            return self._parse_requirements_txt(dep_file)
        elif dep_file.name == "pyproject.toml":
            return self._parse_pyproject_toml(dep_file)
        elif dep_file.name == "poetry.lock":
            return self._parse_poetry_lock(dep_file)
        elif dep_file.name == "Pipfile.lock":
            return self._parse_pipfile_lock(dep_file)
        else:
            logger.warning(f"Unsupported Python dependency file: {dep_file}")
            return []

    def _parse_requirements_txt(self, req_file: Path) -> list[Dependency]:
        """Parse requirements.txt file."""
        dependencies = []

        try:
            content = req_file.read_text(encoding="utf-8")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Handle -r, -c, --index-url, --extra-index-url, --find-links
                if line.startswith(
                    ("-r", "-c", "--index-url", "--extra-index-url", "--find-links", "--no-index")
                ):
                    continue

                # Parse package spec
                dep = self._parse_requirement_line(line)
                if dep:
                    dependencies.append(dep)

        except Exception as e:
            logger.error(f"Error parsing {req_file}: {e}")

        return dependencies

    def _parse_requirement_line(self, line: str) -> Dependency | None:
        """Parse a single requirement line."""
        # Pattern: package[extra]==version, package>=version, package~=version, etc.
        # Also handles git+https://, file://, etc.

        # Remove inline comments
        if "#" in line:
            line = line.split("#")[0].strip()

        # Skip empty
        if not line:
            return None

        # Handle editable installs (-e)
        editable = line.startswith("-e ")
        if editable:
            line = line[3:].strip()

        # Handle direct URL references
        if line.startswith(("git+", "hg+", "svn+", "bzr+", "file:", "http:", "https:")):
            # Extract package name from URL if possible
            # For now, skip VCS URLs as they don't have clear versions
            logger.debug(f"Skipping VCS/URL requirement: {line}")
            return None

        # Parse package specifiers
        # package==1.0.0, package>=1.0, package~=1.0, package, package[extra]==1.0
        pattern = r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*((?:==|>=|<=|>|<|~=|!=|===)\s*[^,\s]+)?"
        match = re.match(pattern, line.strip())

        if not match:
            logger.warning(f"Could not parse requirement: {line}")
            return None

        name = match.group(1).lower()
        version_spec = match.group(2).strip() if match.group(2) else ""

        # Clean version spec
        if version_spec:
            # Extract version from specifier (take first version)
            version_match = re.search(r"(?:==|>=|<=|>|<|~=|!=|===)\s*([^,\s]+)", version_spec)
            version = version_match.group(1) if version_match else "unknown"
        else:
            version = "unknown"

        return Dependency(
            name=name,
            version=version,
            ecosystem="pip",
            dev=False,  # requirements.txt doesn't distinguish dev
            source=None,
        )

    def _parse_pyproject_toml(self, pyproject_file: Path) -> list[Dependency]:
        """Parse pyproject.toml for dependencies."""
        dependencies = []

        try:
            content = pyproject_file.read_text(encoding="utf-8")
            data = toml.loads(content)

            # PEP 621 - project.dependencies
            project = data.get("project", {})
            for dep_spec in project.get("dependencies", []):
                dep = self._parse_requirement_line(dep_spec)
                if dep:
                    dependencies.append(dep)

            # Optional dependencies - try multiple formats
            optional_deps = project.get("optional-dependencies", {})
            if isinstance(optional_deps, dict):
                # Format 1: {dev = ["pytest", "black"]} or {dev = ["pytest>=7.0.0", "black>=23.0.0"]}
                for value in optional_deps.values():
                    if isinstance(value, list):
                        for dep_spec in value:
                            dep = self._parse_requirement_line(dep_spec)
                            if dep:
                                dep.dev = True
                                dependencies.append(dep)
                    elif isinstance(value, str):
                        dep = self._parse_requirement_line(value)
                        if dep:
                            dep.dev = True
                            dependencies.append(dep)
                # Poetry dependencies (tool.poetry.dependencies)
            poetry = data.get("tool", {}).get("poetry", {})
            for dep_name, dep_spec in poetry.get("dependencies", {}).items():
                if dep_name.lower() == "python":
                    continue
                dep = self._parse_poetry_dependency(dep_name, dep_spec)
                if dep:
                    dependencies.append(dep)

            # Poetry dev dependencies
            for dep_name, dep_spec in (
                poetry.get("group", {}).get("dev", {}).get("dependencies", {}).items()
            ):
                dep = self._parse_poetry_dependency(dep_name, dep_spec)
                if dep:
                    dep.dev = True
                    dependencies.append(dep)

            # PDM dependencies (tool.pdm.dependencies)
            pdm = data.get("tool", {}).get("pdm", {})
            for dep_name, dep_spec in pdm.get("dependencies", {}).items():
                dep = self._parse_poetry_dependency(dep_name, dep_spec)  # Similar format
                if dep:
                    dependencies.append(dep)

        except Exception as e:
            logger.error(f"Error parsing pyproject.toml: {e}")

        return dependencies

    def _parse_poetry_dependency(self, name: str, spec: Any) -> Dependency | None:
        """Parse Poetry dependency specification."""
        try:
            if isinstance(spec, str):
                version = spec
                dev = False
            elif isinstance(spec, dict):
                version = spec.get("version", "unknown")
                dev = spec.get("dev", False) or spec.get("optional", False)
            else:
                return None

            return Dependency(
                name=name.lower(),
                version=version,
                ecosystem="pip",
                dev=dev,
                source=None,
            )
        except Exception:
            return None

    def _parse_poetry_lock(self, lock_file: Path) -> list[Dependency]:
        """Parse poetry.lock file."""
        dependencies = []
        seen = set()

        try:
            content = lock_file.read_text(encoding="utf-8")

            # Parse manually to handle duplicate [package] sections
            # that the TOML library can't handle
            packages = []
            current_package: dict[str, str] | None = None

            for line in content.splitlines():
                stripped = line.strip()

                # Start of a new package section
                if stripped == "[package]":
                    if current_package:
                        packages.append(current_package)
                    current_package = {}
                    continue

                # If we're inside a package section, parse key-value
                if current_package is not None and "=" in stripped:
                    key, _, value = stripped.partition("=")
                    key = key.strip().lower()
                    value = value.strip().strip('"').strip("'")

                    if key == "name":
                        current_package["name"] = value.lower()
                    elif key == "version":
                        current_package["version"] = value
                    elif key == "category":
                        current_package["category"] = value

            # Add last package
            if current_package:
                packages.append(current_package)

            for pkg in packages:
                name = pkg.get("name", "").lower()
                version = pkg.get("version", "")

                if not name or not version:
                    continue

                # Skip duplicate package names
                if name in seen:
                    continue
                seen.add(name)

                category = pkg.get("category", "main")

                dep = Dependency(
                    name=name,
                    version=version,
                    ecosystem="pip",
                    dev=(category != "main"),
                    license=None,
                    description=pkg.get("description"),
                    source=None,
                )
                dependencies.append(dep)

        except Exception as e:
            logger.error(f"Error parsing poetry.lock: {e}")

        return dependencies

    def _parse_pipfile_lock(self, lock_file: Path) -> list[Dependency]:
        """Parse Pipfile.lock file."""
        dependencies = []

        try:
            content = lock_file.read_text(encoding="utf-8")
            data = json.loads(content)

            for section in ["default", "develop"]:
                for name, info in data.get(section, {}).items():
                    version = info.get("version", "").lstrip("=").strip()
                    if version.startswith("=="):
                        version = version[2:]

                    dep = Dependency(
                        name=name.lower(),
                        version=version or "unknown",
                        ecosystem="pip",
                        dev=(section == "develop"),
                        license=None,
                        description=None,
                        source=info.get("source"),
                    )
                    dependencies.append(dep)

        except Exception as e:
            logger.error(f"Error parsing Pipfile.lock: {e}")

        return dependencies

    def get_lock_files(self, project_root: Path) -> list[Path]:
        """Find Python dependency files in project."""
        files: list[Path] = []
        files.extend(project_root.rglob("requirements.txt"))
        files.extend(project_root.rglob("requirements-dev.txt"))
        files.extend(project_root.rglob("requirements-*.txt"))
        files.extend(project_root.rglob("pyproject.toml"))
        files.extend(project_root.rglob("poetry.lock"))
        files.extend(project_root.rglob("Pipfile.lock"))
        # Remove duplicates while preserving order
        seen = set()
        unique_files = []
        for f in files:
            resolved = str(f.resolve())
            if resolved not in seen:
                seen.add(resolved)
                unique_files.append(f)
        return unique_files

    def get_vulnerable_versions(self, pkg_name: str) -> list[str]:
        """Get known vulnerable version ranges for Python package."""
        vuln_db = {
            "django": [">=1.0,<3.2.19", ">=4.0,<4.2.10", ">=5.0,<5.0.2"],
            "flask": [">=1.0,<2.3.2", ">=2.3.2,<2.3.3"],
            "requests": [">=2.0,<2.28.2", ">=2.28.2,<2.31.0"],
            "urllib3": [">=1.0,<1.26.16", ">=1.26.16,<1.26.18", ">=2.0,<2.0.7"],
            "certifi": [">=2022.12.7,<2023.7.22"],
            "cryptography": [">=3.0,<41.0.4", ">=41.0.4,<41.0.5", ">=41.0.5,<42.0.0"],
            "pyyaml": [">=5.0,<6.0.1"],
            "pillow": [">=8.0,<9.0.1", ">=9.0,<9.2.0", ">=9.2,<10.0.1"],
            "numpy": [">=1.0,<1.24.3", ">=1.24,<1.24.3"],
            "scipy": [">=1.0,<1.10.1", ">=1.10,<1.11.0"],
            "pandas": [">=1.0,<2.0.3"],
            "matplotlib": [">=3.0,<3.7.1"],
            "jinja2": [">=3.0,<3.1.2"],
            "werkzeug": [">=2.0,<2.3.7", ">=2.3.7,<2.3.8"],
            "click": [">=7.0,<8.1.3"],
            "itsdangerous": [">=2.0,<2.1.2"],
            "markupsafe": [">=2.0,<2.1.2"],
            "sqlalchemy": [">=1.4,<2.0.19"],
            "alembic": [">=1.0,<1.11.1"],
            "celery": [">=5.0,<5.2.7", ">=5.2.7,<5.3.0"],
            "redis": [">=4.0,<4.5.5", ">=4.5.5,<4.5.6", ">=5.0,<5.0.1"],
            "psycopg2": [">=2.8,<2.9.7"],
            "psycopg2-binary": [">=2.8,<2.9.7"],
            "pymongo": [">=3.0,<4.4.1"],
            "motor": [">=2.0,<3.3.1"],
            "aioredis": [">=1.0,<2.0.1"],
            "aiohttp": [">=3.0,<3.8.5", ">=3.8.5,<3.8.6"],
            "httpx": [">=0.1,<0.24.1"],
            "fastapi": [
                ">=0.1,<0.100.0",
                ">=0.100,<0.101.0",
                ">=0.101,<0.103.1",
                ">=0.103,<0.109.0",
            ],
            "starlette": [">=0.1,<0.27.0"],
            "uvicorn": [">=0.1,<0.22.0", ">=0.22,<0.23.0", ">=0.23,<0.27.0"],
            "gunicorn": [">=20.0,<21.0.0"],
            "pytest": [">=7.0,<7.4.0"],
            "pytest-cov": [">=4.0,<4.1.0"],
            "pytest-mock": [">=3.0,<3.10.1"],
            "black": [">=22.0,<23.1.0"],
            "isort": [">=5.0,<5.12.0"],
            "mypy": [">=0.9,<1.3.0"],
            "bandit": [">=1.7,<1.7.5"],
            "safety": [">=2.0,<2.3.5"],
            "pip-audit": [">=2.0,<2.6.1"],
            "semgrep": [">=1.0,<1.20.0"],
            "pre-commit": [">=2.0,<3.4.0"],
            "virtualenv": [">=20.0,<20.16.0"],
            "pip": [">=22.0,<23.1", ">=23.1,<23.2", ">=23.2,<24.0"],
            "setuptools": [">=60.0,<65.5.1", ">=65.5.1,<67.0.0", ">=67.0,<68.0.0"],
            "wheel": [">=0.37,<0.40.0"],
            "packaging": [">=20.0,<21.0", ">=21.0,<21.3"],
            "typing-extensions": [">=4.0,<4.5.0"],
            "attrs": [">=21.0,<22.2.0", ">=22.2,<23.1.0"],
            "python-dateutil": [">=2.8,<2.8.2"],
            "charset-normalizer": [">=2.0,<3.2.0"],
            "idna": [">=2.0,<3.4"],
            "multidict": [">=5.0,<6.0.2"],
            "yarl": [">=1.0,<1.9.2"],
            "async-timeout": [">=3.0,<4.0.2"],
            "frozenlist": [">=1.0,<1.4.0"],
            "aiofiles": [">=0.1,<23.1.0"],
            "python-multipart": [">=0.0,<0.0.6"],
            "email-validator": [">=1.0,<2.1.0"],
            "passlib": [">=1.7,<1.7.4"],
            "python-jose": [">=3.0,<3.3.0"],
            "pyjwt": [">=2.0,<2.8.0"],
            "bcrypt": [">=3.0,<4.0.1"],
            "argon2-cffi": [">=20.0,<23.1.0"],
        }
        return vuln_db.get(pkg_name.lower(), [])

    def check_version_vulnerable(self, pkg_name: str, version: str) -> list[dict]:
        """Check if a package version is vulnerable."""
        vuln_ranges = self.get_vulnerable_versions(pkg_name)
        if not vuln_ranges:
            return []

        from packaging import version as pkg_version
        from packaging.specifiers import SpecifierSet

        findings = []
        try:
            v = pkg_version.parse(version)
            for constraint in vuln_ranges:
                try:
                    spec = SpecifierSet(constraint)
                    if spec.contains(v):
                        findings.append(
                            {
                                "constraint": constraint,
                                "matched": True,
                            }
                        )
                except Exception as e:
                    logger.debug(f"Version constraint check failed for {pkg_name}: {e}")
        except Exception as e:
            logger.debug(f"Version check failed for {pkg_name}@{version}: {e}")

        return findings
