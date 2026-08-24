"""Dependency Scanner for LocalGuard-Pro SCA."""

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from localguard.auditors.base import AuditorResult, SCAAuditor
from localguard.auditors.sca.parsers import ComposerParser, NPMParser, PipParser
from localguard.auditors.sca.sources import OfflineCVESource, OSVCVESource
from localguard.core.config import SCAConfig
from localguard.core.constants import Category, Severity
from localguard.core.models import Finding, Target

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityFinding:
    """Represents a vulnerability finding from SCA."""

    package_name: str
    version: str
    ecosystem: str
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float | None
    vulnerable_range: str
    fixed_version: str | None
    references: list[str]
    source: str
    dev_dependency: bool = False


class DependencyScanner(SCAAuditor):
    """Scanner for vulnerable dependencies."""

    def __init__(self):
        super().__init__("Dependencies")
        self.composer_parser = ComposerParser()
        self.npm_parser = NPMParser()
        self.pip_parser = PipParser()
        self.offline_cve = OfflineCVESource()
        self.online_cve: OSVCVESource | None = None

    def _init_online_cve(self, config: SCAConfig) -> None:
        """Initialize online CVE source if enabled."""
        if config.online_cve and self.online_cve is None:
            self.online_cve = OSVCVESource(config)

    async def audit(self, target: Target, config: SCAConfig) -> AuditorResult:
        start_time = time.time()
        findings: list[Finding] = []
        errors: list[str] = []

        try:
            # Initialize online CVE if enabled
            self._init_online_cve(config)

            project_root = Path(target.project_root)
            all_deps: list[Any] = []

            # Parse dependencies from all ecosystems
            if "composer" in config.ecosystems:
                deps = await self._parse_composer_deps(project_root)
                all_deps.extend(deps)

            if "npm" in config.ecosystems:
                deps = await self._parse_npm_deps(project_root)
                all_deps.extend(deps)

            if "pip" in config.ecosystems:
                deps = await self._parse_pip_deps(project_root)
                all_deps.extend(deps)

            logger.info(f"Found {len(all_deps)} total dependencies across all ecosystems")

            # Check each dependency for vulnerabilities
            vuln_findings = await self._check_vulnerabilities(all_deps, config)

            # Convert to Finding objects
            for vuln in vuln_findings:
                findings.append(self._create_finding(vuln, target))

            # Check for deprecated/unmaintained packages
            deprecated_findings = self._check_deprecated_packages(all_deps)
            for dep_find in deprecated_findings:
                findings.append(self._create_finding(dep_find, target))

        except Exception as e:
            errors.append(f"DependencyScanner: {str(e)}")
            logger.exception("DependencyScanner failed")

        return AuditorResult(
            auditor_name=self.name,
            findings=findings,
            errors=errors,
            duration_seconds=time.time() - start_time,
        )

    async def _parse_composer_deps(self, project_root: Path) -> list[Any]:
        """Parse Composer dependencies."""
        deps = []
        lock_files = self.composer_parser.get_lock_files(project_root)

        for lock_file in lock_files:
            try:
                deps.extend(self.composer_parser.parse(lock_file))
            except Exception as e:
                logger.warning(f"Failed to parse {lock_file}: {e}")

        logger.info(f"Parsed {len(deps)} Composer dependencies")
        return deps

    async def _parse_npm_deps(self, project_root: Path) -> list[Any]:
        """Parse NPM/yarn dependencies."""
        deps = []
        lock_files = self.npm_parser.get_lock_files(project_root)

        for lock_file in lock_files:
            try:
                deps.extend(self.npm_parser.parse(lock_file))
            except Exception as e:
                logger.warning(f"Failed to parse {lock_file}: {e}")

        logger.info(f"Parsed {len(deps)} NPM dependencies")
        return deps

    async def _parse_pip_deps(self, project_root: Path) -> list[Any]:
        """Parse Python dependencies."""
        deps = []
        dep_files = self.pip_parser.get_lock_files(project_root)

        for dep_file in dep_files:
            try:
                deps.extend(self.pip_parser.parse(dep_file))
            except Exception as e:
                logger.warning(f"Failed to parse {dep_file}: {e}")

        logger.info(f"Parsed {len(deps)} Python dependencies")
        return deps

    async def _check_vulnerabilities(
        self, dependencies: list[Any], config: SCAConfig
    ) -> list[VulnerabilityFinding]:
        """Check all dependencies for vulnerabilities."""
        vuln_findings = []
        checked: set[str] = set()

        for dep in dependencies:
            # Create unique key for deduplication
            key = f"{dep.ecosystem}:{dep.name}:{dep.version}"
            if key in checked:
                continue
            checked.add(key)

            # Check offline database
            offline_cves = self.offline_cve.query(dep.name, dep.ecosystem, dep.version)

            for cve in offline_cves:
                # Determine matching vulnerable range
                matched_range = ""
                for vr in cve.vulnerable_versions:
                    if self._version_in_range(dep.version, vr):
                        matched_range = vr
                        break

                vuln_findings.append(
                    VulnerabilityFinding(
                        package_name=dep.name,
                        version=dep.version,
                        ecosystem=dep.ecosystem,
                        cve_id=cve.cve_id,
                        title=cve.description,
                        description=cve.description,
                        severity=cve.severity,
                        cvss_score=cve.cvss_score,
                        vulnerable_range=matched_range,
                        fixed_version=cve.fixed_versions[0] if cve.fixed_versions else None,
                        references=cve.references,
                        source="offline",
                        dev_dependency=dep.dev,
                    )
                )

            # Check online CVE source if enabled
            if self.online_cve:
                try:
                    online_vulns = await self.online_cve.query(dep.name, dep.ecosystem, dep.version)
                    for osv_vuln in online_vulns:
                        finding_data = self.online_cve.convert_osv_to_finding(
                            osv_vuln, dep.name, dep.ecosystem, dep.version
                        )
                        vuln_findings.append(
                            VulnerabilityFinding(
                                package_name=dep.name,
                                version=dep.version,
                                ecosystem=dep.ecosystem,
                                cve_id=finding_data["cve_id"],
                                title=finding_data["title"],
                                description=finding_data["description"],
                                severity=finding_data["severity"],
                                cvss_score=finding_data["cvss_score"],
                                vulnerable_range=", ".join(finding_data["affected_versions"]),
                                fixed_version=(
                                    finding_data["fixed_versions"][0]
                                    if finding_data["fixed_versions"]
                                    else None
                                ),
                                references=finding_data["references"],
                                source="OSV.dev",
                                dev_dependency=dep.dev,
                            )
                        )
                except Exception as e:
                    logger.debug(f"Online CVE check failed for {dep.name}: {e}")

        return vuln_findings

    def _check_deprecated_packages(self, dependencies: list[Any]) -> list[VulnerabilityFinding]:
        """Check for deprecated/unmaintained packages."""
        findings = []

        # Known deprecated packages (simplified - would be from database in production)
        deprecated: dict[str, dict[str, dict[str, str] | str]] = {
            "composer": {
                "laravel/framework": {"v8": "Use v9 or v10", "v9": "Use v10"},
                "symfony/symfony": {"v4": "Use v5 or v6", "v5": "Use v6"},
                "doctrine/orm": {"v2": "Use v3"},
            },
            "npm": {
                "request": "Deprecated - use fetch/axios",
                "har-validator": "Deprecated - no longer maintained",
                "fsevents": "v1 deprecated - use v2",
                "chokidar": "v2 deprecated - use v3",
                "urix": "Deprecated - use native URL",
                "resolve-url": "Deprecated - use native URL",
            },
            "pip": {
                "distribute": "Merged into setuptools",
                "nose": "Use pytest instead",
                "mock": "Built into unittest.mock (py3.3+)",
                "pathlib2": "Built into pathlib (py3.4+)",
                "backports.functools_lru_cache": "Built into functools (py3.2+)",
                "typing": "Built into typing (py3.5+)",
            },
        }

        for dep in dependencies:
            dep_key = dep.name.lower()
            if dep.ecosystem in deprecated and dep_key in deprecated[dep.ecosystem]:
                info = deprecated[dep.ecosystem][dep_key]
                if isinstance(info, dict):
                    # Check version-specific deprecation
                    for version_range, message in info.items():
                        if self._version_in_range(dep.version, version_range):
                            findings.append(
                                VulnerabilityFinding(
                                    package_name=dep.name,
                                    version=dep.version,
                                    ecosystem=dep.ecosystem,
                                    cve_id="DEPRECATED",
                                    title=f"Deprecated Package: {dep.name}",
                                    description=f"{dep.name} is deprecated: {message}",
                                    severity="Medium",
                                    cvss_score=None,
                                    vulnerable_range=version_range,
                                    fixed_version=None,
                                    references=[],
                                    source="deprecation_db",
                                    dev_dependency=dep.dev,
                                )
                            )
                else:
                    findings.append(
                        VulnerabilityFinding(
                            package_name=dep.name,
                            version=dep.version,
                            ecosystem=dep.ecosystem,
                            cve_id="DEPRECATED",
                            title=f"Deprecated Package: {dep.name}",
                            description=f"{dep.name} is deprecated: {info}",
                            severity="Low",
                            cvss_score=None,
                            vulnerable_range="all",
                            fixed_version=None,
                            references=[],
                            source="deprecation_db",
                            dev_dependency=dep.dev,
                        )
                    )

        return findings

    def _version_in_range(self, version: str, constraint: str) -> bool:
        """Check if version matches constraint."""
        from packaging import version as pkg_version
        from packaging.specifiers import SpecifierSet

        try:
            v = pkg_version.parse(version)
            spec = SpecifierSet(constraint)
            return spec.contains(v)
        except Exception:
            return False

    def _create_finding(self, vuln: VulnerabilityFinding, target: Target) -> Finding:  # type: ignore[override]  # noqa
        """Convert vulnerability finding to Finding object."""
        # Build endpoint
        endpoint = f"{vuln.ecosystem}:{vuln.package_name}@{vuln.version}"
        if vuln.dev_dependency:
            endpoint += " (dev)"

        # Build evidence
        evidence_parts = [
            f"Package: {vuln.package_name}",
            f"Version: {vuln.version}",
            f"Ecosystem: {vuln.ecosystem}",
        ]
        if vuln.vulnerable_range:
            evidence_parts.append(f"Vulnerable range: {vuln.vulnerable_range}")
        if vuln.fixed_version:
            evidence_parts.append(f"Fixed in: {vuln.fixed_version}")
        if vuln.cvss_score:
            evidence_parts.append(f"CVSS: {vuln.cvss_score}")

        evidence = "; ".join(evidence_parts)

        # Build remediation
        remediation = (
            f"Update {vuln.package_name} to version {vuln.fixed_version or 'latest non-vulnerable'}"
        )
        if vuln.cve_id != "DEPRECATED":
            remediation += f" to fix {vuln.cve_id}"
        else:
            remediation = f"Replace deprecated package {vuln.package_name}"

        severity_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
        }
        finding_severity = severity_map.get(vuln.severity, Severity.LOW)

        return Finding(
            id=f"LG-SCA-{vuln.cve_id}-{vuln.package_name.replace('/', '-')}",
            severity=finding_severity,
            category=Category.SCA,
            title=f"Vulnerable Dependency: {vuln.package_name} {vuln.version}",
            endpoint=f"{vuln.ecosystem}:{vuln.package_name}",
            parameter=vuln.version,
            evidence=evidence,
            impact=f"Vulnerable dependency {vuln.package_name} {vuln.version} ({vuln.severity})"
            + (f" - {vuln.description}" if vuln.description else ""),
            remediation=remediation,
            cwe="CWE-1104",
            owasp="A06:2021 - Vulnerable and Outdated Components",
            references=vuln.references,
        )

    async def _check_package_vulnerabilities(
        self, dep: Any, config: SCAConfig
    ) -> list[VulnerabilityFinding]:
        """Check a single package for vulnerabilities (for parallel processing)."""
        # This is handled in _check_vulnerabilities above
        return []
