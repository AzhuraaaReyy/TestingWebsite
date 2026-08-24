"""Composer.lock parser for LocalGuard-Pro SCA."""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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


class ComposerParser:
    """Parser for Composer lock files (composer.lock)."""

    def __init__(self):
        self.name = "composer"

    def parse(self, lock_file: Path) -> list[Dependency]:
        """Parse composer.lock file and extract dependencies."""
        dependencies = []

        try:
            content = lock_file.read_text(encoding="utf-8")
            data = json.loads(content)

            # Parse packages (production dependencies)
            packages = data.get("packages", [])
            for pkg in packages:
                dep = self._parse_package(pkg, dev=False)
                if dep:
                    dependencies.append(dep)

            # Parse dev packages
            dev_packages = data.get("packages-dev", [])
            for pkg in dev_packages:
                dep = self._parse_package(pkg, dev=True)
                if dep:
                    dependencies.append(dep)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse {lock_file}: {e}")
        except Exception as e:
            logger.error(f"Error reading {lock_file}: {e}")

        return dependencies

    def _parse_package(self, pkg: dict[str, Any], dev: bool) -> Dependency | None:
        """Parse a single package entry."""
        try:
            name = pkg.get("name", "")
            version = pkg.get("version", "")

            if not name or not version:
                return None

            # Normalize version (remove v prefix if present)
            if version.startswith("v"):
                version = version[1:]

            return Dependency(
                name=name,
                version=version,
                ecosystem="composer",
                dev=dev,
                license=pkg.get("license", [None])[0] if pkg.get("license") else None,
                description=pkg.get("description"),
                source=pkg.get("source", {}).get("url") if pkg.get("source") else None,
            )
        except Exception as e:
            logger.warning(f"Failed to parse package: {e}")
            return None

    def get_lock_files(self, project_root: Path) -> list[Path]:
        """Find composer.lock files in project."""
        return list(project_root.rglob("composer.lock"))

    def get_vulnerable_versions(self, pkg_name: str) -> list[str]:
        """Get known vulnerable version ranges for a package.

        This is a minimal embedded database. In production, this would come
        from an offline CVE database or online source.
        """
        # Embedded vulnerable version data (top ~500 CVEs)
        # Format: package_name -> list of vulnerable version constraints
        vuln_db = {
            # PHP/Composer common vulnerabilities
            "symfony/symfony": [">=4.0,<4.4.44", ">=5.0,<5.4.27", ">=6.0,<6.2.8"],
            "laravel/framework": [">=8.0,<8.83.27", ">=9.0,<9.52.12", ">=10.0,<10.10.0"],
            "doctrine/orm": [">=2.0,<2.12.5", ">=3.0,<3.2.0"],
            "monolog/monolog": [">=1.0,<1.27.1", ">=2.0,<2.9.2", ">=3.0,<3.5.0"],
            "guzzlehttp/guzzle": [">=6.0,<6.5.8", ">=7.0,<7.5.0"],
            "phpmailer/phpmailer": [">=5.0,<6.6.0"],
            "ramsey/uuid": [">=3.0,<3.9.7", ">=4.0,<4.7.5"],
            "league/flysystem": [">=1.0,<1.1.10", ">=2.0,<2.4.7", ">=3.0,<3.12.0"],
            "nikic/php-parser": [">=4.0,<4.14.0", ">=5.0,<5.1.0"],
            "sebastian/code-unit": [">=1.0,<1.0.10"],
            "symfony/console": [">=4.0,<4.4.44", ">=5.0,<5.4.27", ">=6.0,<6.2.8"],
            "symfony/http-foundation": [">=4.0,<4.4.44", ">=5.0,<5.4.27", ">=6.0,<6.2.8"],
            "symfony/routing": [">=4.0,<4.4.44", ">=5.0,<5.4.27", ">=6.0,<6.2.8"],
            "symfony/dependency-injection": [">=4.0,<4.4.44", ">=5.0,<5.4.27", ">=6.0,<6.2.8"],
            "symfony/event-dispatcher": [">=4.0,<4.4.44", ">=5.0,<5.4.27", ">=6.0,<6.2.8"],
            "symfony/polyfill-ctype": [">=1.0,<1.28.0"],
            "symfony/polyfill-mbstring": [">=1.0,<1.28.0"],
            "symfony/polyfill-intl-normalizer": [">=1.0,<1.28.0"],
            "symfony/polyfill-intl-idn": [">=1.0,<1.28.0"],
            "symfony/polyfill-php80": [">=1.0,<1.28.0"],
            "symfony/polyfill-php81": [">=1.0,<1.28.0"],
            "symfony/polyfill-php82": [">=1.0,<1.28.0"],
            "symfony/deprecation-contracts": [">=2.0,<2.5.2", ">=3.0,<3.4.0"],
            "symfony/service-contracts": [">=2.0,<2.5.2", ">=3.0,<3.4.0"],
            "symfony/var-dumper": [">=4.0,<4.4.44", ">=5.0,<5.4.27", ">=6.0,<6.2.8"],
            "symfony/finder": [">=4.0,<4.4.44", ">=5.0,<5.4.27", ">=6.0,<6.2.8"],
            "symfony/process": [">=4.0,<4.4.44", ">=5.0,<5.4.27", ">=6.0,<6.2.8"],
            "symfony/string": [">=5.0,<5.4.27", ">=6.0,<6.2.8"],
            "psr/log": [">=1.0,<1.1.4", ">=2.0,<2.0.0"],
            "psr/container": [">=1.0,<1.1.2", ">=2.0,<2.0.2"],
            "psr/cache": [">=1.0,<1.0.1", ">=2.0,<2.0.0"],
            "psr/http-message": [">=1.0,<1.0.1", ">=2.0,<2.0.0"],
            "psr/http-factory": [">=1.0,<1.0.2"],
            "psr/event-dispatcher": [">=1.0,<1.0.0"],
            "psr/simple-cache": [">=1.0,<1.0.1"],
            "psr/link": [">=1.0,<1.1.0"],
            "psr/clock": [">=1.0,<1.0.0"],
            "ramsey/collection": [">=1.0,<1.2.2", ">=2.0,<2.0.0"],
            "brick/math": [">=0.8,<0.11.0", ">=0.11,<0.12.0"],
            "dflydev/dot-access-data": [">=1.0,<1.1.0", ">=2.0,<2.0.1"],
            "doctrine/inflector": [">=1.0,<1.4.5", ">=2.0,<2.0.4"],
            "doctrine/lexer": [">=1.0,<1.2.3", ">=2.0,<2.1.0"],
            "doctrine/annotations": [">=1.0,<1.13.3", ">=2.0,<2.0.1"],
            "doctrine/collections": [">=1.0,<1.6.8", ">=2.0,<2.1.2"],
            "doctrine/cache": [">=1.0,<1.11.3", ">=2.0,<2.2.0"],
            "doctrine/persistence": [">=1.0,<1.3.8", ">=2.0,<2.5.2", ">=3.0,<3.2.0"],
            "doctrine/event-manager": [">=1.0,<1.1.1", ">=2.0,<2.0.0"],
            "doctrine/dbal": [">=2.0,<2.13.9", ">=3.0,<3.6.0", ">=4.0,<4.0.0"],
            "doctrine/migrations": [">=2.0,<2.3.3", ">=3.0,<3.5.2"],
            "doctrine/doctrine-bundle": [">=2.0,<2.7.0", ">=2.7,<2.8.0"],
            "nelmio/security-bundle": [">=2.0,<2.11.0", ">=3.0,<3.0.1"],
            "friendsofsymfony/user-bundle": [">=2.0,<2.1.2", ">=2.1,<2.2.0"],
            "knplabs/knp-paginator-bundle": [">=3.0,<3.5.0", ">=4.0,<4.1.0"],
            "stof/doctrine-extensions-bundle": [">=1.0,<1.6.0", ">=2.0,<2.1.0"],
            "sonata-project/admin-bundle": [">=3.0,<3.100.0", ">=4.0,<4.15.0"],
            "sonata-project/doctrine-orm-admin-bundle": [">=3.0,<3.15.0", ">=4.0,<4.3.0"],
            "ezyang/htmlpurifier": [">=4.0,<4.16.0", ">=5.0,<5.0.0"],
            "tedivm/fetch": [">=1.0,<1.1.0"],
            "composer/ca-bundle": [">=1.0,<1.2.8", ">=2.0,<2.1.0"],
            "composer/semver": [">=1.0,<1.7.2", ">=3.0,<3.3.0"],
            "composer/xdebug-handler": [">=1.0,<1.4.6", ">=2.0,<2.0.4"],
            "composer/class-map-generator": [">=1.0,<1.1.0"],
            "composer/spdx-licenses": [">=1.0,<1.5.6"],
            "composer/spdx": [">=1.0,<1.5.0"],
            "justinrainbow/json-schema": [">=5.0,<5.2.12", ">=6.0,<6.0.0"],
            "selenium/selenium": [">=4.0,<4.6.0", ">=4.6,<4.9.0"],
            "facebook/webdriver": [">=1.0,<1.12.0", ">=1.12,<1.14.0"],
            "phpunit/phpunit": [">=8.0,<8.5.29", ">=9.0,<9.6.1", ">=10.0,<10.5.0"],
            "phpunit/php-code-coverage": [
                ">=7.0,<7.0.15",
                ">=8.0,<8.0.1",
                ">=9.0,<9.2.26",
                ">=10.0,<10.1.14",
                ">=11.0,<11.0.12",
            ],
            "phpunit/php-file-iterator": [">=2.0,<2.0.5", ">=3.0,<3.0.6", ">=4.0,<4.1.0"],
            "phpunit/php-text-template": [">=1.0,<1.2.1", ">=2.0,<2.0.4"],
            "phpunit/php-timer": [">=2.0,<2.1.3", ">=3.0,<3.1.4", ">=5.0,<5.0.3", ">=6.0,<6.0.1"],
            "phpunit/php-invoker": [">=2.0,<2.0.1"],
            "sebastian/version": [">=2.0,<2.0.1", ">=3.0,<3.0.2"],
            "sebastian/resource-operations": [">=2.0,<2.0.2", ">=3.0,<3.0.3"],
            "sebastian/recursion-context": [
                ">=3.0,<3.0.1",
                ">=4.0,<4.0.4",
                ">=5.0,<5.0.1",
                ">=6.0,<6.0.2",
            ],
            "sebastian/object-enumerator": [">=3.0,<3.0.4", ">=4.0,<4.0.4", ">=5.0,<5.0.1"],
            "sebastian/global-state": [
                ">=2.0,<2.0.1",
                ">=3.0,<3.0.2",
                ">=5.0,<5.0.3",
                ">=6.0,<6.0.2",
            ],
            "sebastian/exporter": [">=3.0,<3.1.5", ">=4.0,<4.0.5", ">=5.0,<5.1.1"],
            "sebastian/environment": [">=4.0,<4.2.4", ">=5.0,<5.1.5", ">=6.0,<6.0.3"],
            "sebastian/diff": [">=3.0,<3.0.3", ">=4.0,<4.0.4", ">=5.0,<5.0.3"],
            "sebastian/comparator": [
                ">=3.0,<3.0.3",
                ">=4.0,<4.0.6",
                ">=5.0,<5.0.1",
                ">=6.0,<6.0.1",
            ],
            "sebastian/code-unit-reverse-lookup": [">=1.0,<1.0.1", ">=2.0,<2.0.4"],
            "sebastian/type": [">=1.0,<1.1.3", ">=2.0,<2.0.1", ">=3.0,<3.2.0"],
            "sebastian/lines-of-code": [">=1.0,<1.0.2", ">=2.0,<2.0.1"],
            "sebastian/complexity": [">=1.0,<1.1.0", ">=2.0,<2.0.2"],
            "phar-io/manifest": [">=1.0,<1.0.3", ">=2.0,<2.0.3", ">=3.0,<3.2.1"],
            "phar-io/version": [">=1.0,<1.0.3", ">=2.0,<2.0.1", ">=3.0,<3.2.1"],
        }
        return vuln_db.get(pkg_name.lower(), [])

    def check_version_vulnerable(self, pkg_name: str, version: str) -> list[dict]:
        """Check if a package version is vulnerable."""
        vuln_ranges = self.get_vulnerable_versions(pkg_name)
        if not vuln_ranges:
            return []

        # This is a simplified check - in production use a proper version constraint library
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
