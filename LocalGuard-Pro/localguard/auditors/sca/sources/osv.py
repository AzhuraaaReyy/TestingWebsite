"""OSV.dev API client for online CVE lookup."""

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from localguard.core.config import SCAConfig

logger = logging.getLogger(__name__)


@dataclass
class OSVCVE:
    """Represents a CVE from OSV.dev."""

    id: str
    summary: str
    details: str
    severity: str
    cvss_score: float | None
    affected_packages: list[dict[str, Any]]
    references: list[str]
    published: str | None
    modified: str | None
    schema_version: str = "1.4.0"


class OSVCVESource:
    """Online CVE source using OSV.dev API."""

    def __init__(self, config: SCAConfig):
        self.config = config
        self.name = "osv"
        self.base_url = "https://api.osv.dev/v1"
        self._cache: dict[str, Any] = {}
        self._cache_file = Path.home() / ".cache" / "localguard" / "osv_cache.json"
        self._load_cache()

    def _load_cache(self) -> None:
        """Load cached CVE data."""
        if self._cache_file.exists():
            try:
                content = self._cache_file.read_text(encoding="utf-8")
                cache_data = json.loads(content)
                # Filter expired entries
                now = time.time()
                ttl = self.config.cache_ttl_hours * 3600
                for key, value in cache_data.items():
                    if now - value.get("timestamp", 0) < ttl:
                        self._cache[key] = value
                logger.info(f"Loaded {len(self._cache)} cached OSV entries")
            except Exception as e:
                logger.warning(f"Failed to load OSV cache: {e}")

    def _save_cache(self) -> None:
        """Save cache to disk."""
        try:
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            # Add timestamp to all entries
            cache_data = {}
            for key, value in self._cache.items():
                cache_data[key] = {
                    **value,
                    "timestamp": time.time(),
                }
            self._cache_file.write_text(json.dumps(cache_data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Failed to save OSV cache: {e}")

    def _make_cache_key(self, package_name: str, ecosystem: str, version: str) -> str:
        """Generate cache key for a package query."""
        return hashlib.sha256(f"{ecosystem}:{package_name}:{version}".encode()).hexdigest()[:16]

    async def query(self, package_name: str, ecosystem: str, version: str) -> list[dict]:
        """Query OSV.dev for vulnerabilities."""
        cache_key = self._make_cache_key(package_name, ecosystem, version)

        # Check cache first
        if cache_key in self._cache:
            cached: dict = self._cache[cache_key]
            if time.time() - cached["timestamp"] < self.config.cache_ttl_hours * 3600:
                logger.debug(f"OSV cache hit for {ecosystem}:{package_name}@{version}")
                data: list[dict] = cached["data"]
                return data

        # Query OSV.dev API
        try:
            vulns = await self._query_osv_api(package_name, ecosystem, version)

            # Cache results
            self._cache[cache_key] = {
                "data": vulns,
                "timestamp": time.time(),
            }
            self._save_cache()

            return vulns
        except Exception as e:
            logger.error(f"OSV query failed for {ecosystem}:{package_name}@{version}: {e}")
            return []

    async def _query_osv_api(self, package_name: str, ecosystem: str, version: str) -> list[dict]:
        """Query OSV.dev API for vulnerabilities."""
        # Map ecosystem names
        ecosystem_map = {
            "composer": "Packagist",
            "npm": "npm",
            "pip": "PyPI",
        }
        osv_ecosystem = ecosystem_map.get(ecosystem.lower(), ecosystem)

        # Build query
        query = {
            "package": {
                "name": package_name,
                "ecosystem": osv_ecosystem,
            },
            "version": version,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/query",
                    json=query,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                data = response.json()

                vulns: list[dict] = data.get("vulns", [])
                logger.info(
                    f"OSV found {len(vulns)} vulnerabilities for {ecosystem}:{package_name}@{version}"
                )
                return vulns
            except httpx.HTTPStatusError as e:
                logger.warning(f"OSV API error: {e.response.status_code}")
                return []
            except Exception as e:
                logger.error(f"OSV query failed: {e}")
                return []

    def convert_osv_to_finding(
        self, osv_vuln: dict, package_name: str, ecosystem: str, version: str
    ) -> dict:
        """Convert OSV vulnerability to finding format."""
        # Extract severity
        severity = "Medium"
        cvss_score = None
        for severity_info in osv_vuln.get("severity", []):
            if severity_info.get("type") == "CVSS_V3":
                cvss_score = severity_info.get("score")
                if cvss_score >= 9.0:
                    severity = "Critical"
                elif cvss_score >= 7.0:
                    severity = "High"
                elif cvss_score >= 4.0:
                    severity = "Medium"
                else:
                    severity = "Low"
                break

        # Extract affected versions
        affected_versions = []
        fixed_versions = []
        for affected in osv_vuln.get("affected", []):
            for range_info in affected.get("ranges", []):
                if range_info.get("type") == "ECOSYSTEM":
                    for event in range_info.get("events", []):
                        if "introduced" in event:
                            affected_versions.append(f">={event['introduced']}")
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])
                        if "last_affected" in event:
                            affected_versions.append(f"<={event['last_affected']}")

        # Extract references
        references = []
        for ref in osv_vuln.get("references", []):
            references.append(ref.get("url", ""))

        return {
            "cve_id": osv_vuln.get("id", "UNKNOWN"),
            "title": osv_vuln.get("summary", "Vulnerability found via OSV.dev"),
            "description": osv_vuln.get("details", ""),
            "severity": severity,
            "cvss_score": cvss_score,
            "affected_versions": affected_versions,
            "fixed_versions": fixed_versions,
            "references": references,
            "source": "OSV.dev",
        }
