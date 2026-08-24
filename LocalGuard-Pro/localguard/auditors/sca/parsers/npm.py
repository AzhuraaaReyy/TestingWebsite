"""NPM/yarn lock file parser for LocalGuard-Pro SCA."""

import json
import logging
import re
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


class NPMParser:
    """Parser for NPM/yarn lock files (package-lock.json, yarn.lock)."""

    def __init__(self):
        self.name = "npm"

    def parse(self, lock_file: Path) -> list[Dependency]:
        """Parse package-lock.json or yarn.lock file."""
        if lock_file.name == "yarn.lock":
            return self._parse_yarn_lock(lock_file)
        else:
            return self._parse_package_lock(lock_file)

    def _parse_package_lock(self, lock_file: Path) -> list[Dependency]:
        """Parse package-lock.json (v1, v2, v3)."""
        dependencies = []

        try:
            content = lock_file.read_text(encoding="utf-8")
            data = json.loads(content)

            # Determine lockfile version
            lockfile_version = data.get("lockfileVersion", 1)

            if lockfile_version >= 2:
                # v2/v3 format - packages in "packages" object
                dependencies.extend(self._parse_packages_v2(data.get("packages", {})))
            else:
                # v1 format - dependencies in "dependencies" object
                dependencies.extend(self._parse_dependencies_v1(data.get("dependencies", {})))

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse {lock_file}: {e}")
        except Exception as e:
            logger.error(f"Error reading {lock_file}: {e}")

        return dependencies

    def _parse_packages_v2(self, packages: dict[str, Any]) -> list[Dependency]:
        """Parse packages object from package-lock.json v2/v3."""
        dependencies = []

        for path, pkg_info in packages.items():
            if path == "" or path == "node_modules":
                continue

            # Extract name from path (node_modules/pkg-name)
            name = path.replace("node_modules/", "")
            if not name:
                continue

            version = pkg_info.get("version", "")
            dev = pkg_info.get("dev", False)
            optional = pkg_info.get("optional", False)

            # Skip optional dependencies that aren't installed
            if optional and not pkg_info.get("dependencies"):
                continue

            dep = Dependency(
                name=name,
                version=version,
                ecosystem="npm",
                dev=dev,
                license=pkg_info.get("license"),
                description=pkg_info.get("description"),
                source=pkg_info.get("resolved"),
            )
            dependencies.append(dep)

        return dependencies

    def _parse_dependencies_v1(self, deps: dict[str, Any]) -> list[Dependency]:
        """Parse dependencies from package-lock.json v1."""
        dependencies = []

        def parse_dep(name: str, info: dict[str, Any], dev: bool = False, path: str = ""):
            version = info.get("version", "")
            dep = Dependency(
                name=name,
                version=version,
                ecosystem="npm",
                dev=dev,
                license=info.get("license"),
                description=info.get("description"),
                source=info.get("resolved"),
            )
            dependencies.append(dep)

            # Parse nested dependencies
            for dep_name, dep_info in info.get("dependencies", {}).items():
                parse_dep(dep_name, dep_info, dev, f"{path}/{dep_name}")

        for name, info in deps.items():
            parse_dep(name, info, info.get("dev", False))

        return dependencies

    def _parse_yarn_lock(self, lock_file: Path) -> list[Dependency]:
        """Parse yarn.lock file."""
        dependencies = []

        try:
            content = lock_file.read_text(encoding="utf-8")
            # Simple regex-based parsing for yarn.lock
            # Format: "pkg@version:" or "pkg@version, pkg2@version2:"
            pattern = r'^([^@\s]+)@([^:\s]+):\s*(?:\n\s+version "([^"]+)")?'

            for match in re.finditer(pattern, content, re.MULTILINE):
                name = match.group(1)
                version_spec = match.group(2)
                version = match.group(3) or version_spec

                # Clean up version
                version = version.strip().strip('"')

                dep = Dependency(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    dev=False,  # yarn.lock doesn't easily distinguish dev/prod
                    source=None,
                )
                dependencies.append(dep)

        except Exception as e:
            logger.error(f"Error parsing yarn.lock {lock_file}: {e}")

        return dependencies

    def get_lock_files(self, project_root: Path) -> list[Path]:
        """Find package-lock.json and yarn.lock files in project."""
        files: list[Path] = []
        files.extend(project_root.rglob("package-lock.json"))
        files.extend(project_root.rglob("yarn.lock"))
        return files

    def get_vulnerable_versions(self, pkg_name: str) -> list[str]:
        """Get known vulnerable version ranges for NPM package."""
        # Embedded vulnerable version data for common NPM packages
        vuln_db = {
            # JavaScript/TypeScript common vulnerabilities
            "lodash": [">=4.0.0 <4.17.21"],
            "jquery": [">=1.0.0 <3.5.0"],
            "moment": [">=2.0.0 <2.29.2"],
            "moment-timezone": [">=0.5.0 <0.5.43"],
            "request": [">=2.0.0 <2.88.2"],
            "tar": [">=2.0.0 <4.4.19", ">=5.0.0 <5.0.5", ">=6.0.0 <6.1.2"],
            "fstream": [">=0.1.0 <1.0.12"],
            "tough-cookie": [">=2.0.0 <2.5.0", ">=4.0.0 <4.1.3"],
            "node-forge": [">=0.1.0 <1.3.1"],
            "js-yaml": [">=3.0.0 <3.14.0", ">=4.0.0 <4.1.0"],
            "handlebars": [">=4.0.0 <4.7.7"],
            "minimist": [">=1.0.0 <1.2.6"],
            "yargs-parser": [">=5.0.0 <18.1.3"],
            "yargs": [">=1.0.0 <15.4.1", ">=15.4.1 <16.2.3", ">=16.2.3 <17.5.1"],
            "shell-quote": [">=1.0.0 <1.7.3"],
            "postcss": [">=7.0.0 <7.0.36", ">=8.0.0 <8.2.10"],
            "browserslist": [">=4.0.0 <4.16.6", ">=4.16.6 <4.19.1"],
            "caniuse-lite": [">=1.0.0 <1.0.30001418"],
            "color-string": [">=1.0.0 <1.9.0"],
            "d3-color": [">=1.0.0 <3.1.0"],
            "d3-geo": [">=1.0.0 <3.0.1"],
            "d3-array": [">=1.0.0 <3.2.4"],
            "d3-axis": [">=1.0.0 <3.0.0"],
            "d3-brush": [">=1.0.0 <3.0.0"],
            "d3-chord": [">=1.0.0 <3.0.1"],
            "d3-collection": [">=1.0.0 <1.0.7"],
            "d3-contour": [">=1.0.0 <4.0.2"],
            "d3-dispatch": [">=1.0.0 <3.0.1"],
            "d3-drag": [">=1.0.0 <3.0.0"],
            "d3-dsv": [">=1.0.0 <3.0.1"],
            "d3-ease": [">=1.0.0 <3.0.1"],
            "d3-fetch": [">=1.0.0 <3.0.1"],
            "d3-force": [">=1.0.0 <3.0.0"],
            "d3-format": [">=1.0.0 <3.1.0"],
            "d3-geo-projection": [">=2.0.0 <4.0.0"],
            "d3-hierarchy": [">=1.0.0 <3.1.2"],
            "d3-interpolate": [">=1.0.0 <3.0.1"],
            "d3-path": [">=1.0.0 <3.0.1"],
            "d3-polygon": [">=1.0.0 <3.0.1"],
            "d3-quadtree": [">=1.0.0 <3.0.1"],
            "d3-random": [">=1.0.0 <3.0.1"],
            "d3-sankey": [">=0.1.0 <0.12.3"],
            "d3-scale": [">=1.0.0 <3.3.0", ">=4.0.0 <4.0.2"],
            "d3-scale-chromatic": [">=1.0.0 <3.0.0"],
            "d3-selection": [">=1.0.0 <3.0.0"],
            "d3-shape": [">=1.0.0 <3.2.0"],
            "d3-time": [">=1.0.0 <3.1.0"],
            "d3-time-format": [">=2.0.0 <4.1.0"],
            "d3-timer": [">=1.0.0 <3.0.1"],
            "d3-transition": [">=1.0.0 <3.0.1"],
            "d3-voronoi": [">=1.0.0 <1.1.4"],
            "d3-zoom": [">=1.0.0 <3.0.0"],
            "express": [">=4.0.0 <4.18.2"],
            "koa": [">=2.0.0 <2.14.0"],
            "debug": [">=0.1.0 <4.3.4"],
            "ms": [">=0.1.0 <2.1.3"],
            "uuid": [">=2.0.0 <8.3.2", ">=8.3.2 <9.0.0"],
            "validator": [">=1.0.0 <13.7.0"],
            "minimatch": [">=1.0.0 <3.1.2", ">=3.1.2 <5.1.6", ">=5.1.6 <9.0.3"],
            "brace-expansion": [">=1.0.0 <1.1.11", ">=2.0.0 <2.0.1"],
            "glob": [">=7.0.0 <7.2.3", ">=7.2.3 <8.0.3", ">=8.0.3 <10.3.0"],
            "rimraf": [">=2.0.0 <3.0.2", ">=3.0.2 <4.0.5"],
            "mkdirp": [">=0.5.0 <1.0.4"],
            "nopt": [">=1.0.0 <5.0.1"],
            "isexe": [">=1.0.0 <2.0.0"],
            "cross-spawn": [">=1.0.0 <7.0.3"],
            "signal-exit": [">=1.0.0 <3.0.7", ">=3.0.7 <4.1.0"],
            "strip-final-newline": [">=1.0.0 <2.0.0", ">=2.0.0 <3.0.0"],
            "execa": [">=0.1.0 <5.1.1", ">=5.1.1 <6.1.0"],
            "npm-run-path": [">=1.0.0 <4.0.1", ">=4.0.1 <5.1.0"],
            "path-key": [">=1.0.0 <3.1.1"],
            "shebang-command": [">=1.0.0 <2.0.0"],
            "shebang-regex": [">=1.0.0 <3.0.0"],
            "which": [">=1.0.0 <2.0.2", ">=2.0.2 <3.0.0"],
            "acorn": [">=5.0.0 <8.8.1"],
            "acorn-jsx": [">=3.0.0 <5.3.1"],
            "acorn-walk": [">=6.0.0 <8.2.0"],
            "eslint": [">=1.0.0 <8.56.0"],
            "eslint-plugin-react": [">=7.0.0 <7.33.2"],
            "eslint-plugin-jsx-a11y": [">=1.0.0 <6.7.1"],
            "eslint-plugin-import": [">=1.0.0 <2.28.1"],
            "@babel/core": [">=7.0.0 <7.23.0"],
            "@babel/parser": [">=7.0.0 <7.23.0"],
            "@babel/traverse": [">=7.0.0 <7.23.0"],
            "@babel/generator": [">=7.0.0 <7.23.0"],
            "@babel/types": [">=7.0.0 <7.23.0"],
            "@babel/template": [">=7.0.0 <7.23.0"],
            "@babel/helper-plugin-utils": [">=7.0.0 <7.22.0"],
            "@babel/helper-function-name": [">=7.0.0 <7.23.0"],
            "@babel/helper-split-export-declaration": [">=7.0.0 <7.22.0"],
            "@babel/helper-validator-identifier": [">=7.0.0 <7.22.0"],
            "@babel/helper-validator-option": [">=7.0.0 <7.22.0"],
            "@babel/helper-module-imports": [">=7.0.0 <7.22.0"],
            "@babel/helper-replace-supers": [">=7.0.0 <7.22.0"],
            "@babel/helper-create-class-features-plugin": [">=7.0.0 <7.22.0"],
            "@babel/plugin-syntax-typescript": [">=7.0.0 <7.22.0"],
            "@babel/plugin-transform-typescript": [">=7.0.0 <7.22.0"],
            "@babel/preset-typescript": [">=7.0.0 <7.22.0"],
            "@babel/preset-react": [">=7.0.0 <7.22.0"],
            "@babel/preset-env": [">=7.0.0 <7.23.0"],
            "typescript": [">=4.0.0 <5.2.2"],
            "tslib": [">=1.0.0 <2.6.2"],
            "webpack": [">=4.0.0 <5.88.2"],
            "webpack-cli": [">=3.0.0 <5.1.4"],
            "vite": [">=2.0.0 <5.0.0"],
            "rollup": [">=2.0.0 <4.0.0"],
            "next": [">=10.0.0 <14.0.0"],
            "react": [">=16.0.0 <18.2.0"],
            "react-dom": [">=16.0.0 <18.2.0"],
            "react-router": [">=5.0.0 <6.20.0"],
            "react-router-dom": [">=5.0.0 <6.20.0"],
            "redux": [">=4.0.0 <4.2.1"],
            "react-redux": [">=7.0.0 <8.1.3"],
            "@reduxjs/toolkit": [">=1.0.0 <2.0.0"],
            "axios": [">=0.1.0 <1.6.2"],
            "fetch": [">=1.0.0 <2.0.0"],
            "socket.io": [">=2.0.0 <4.7.2"],
            "socket.io-client": [">=2.0.0 <4.7.2"],
            "engine.io": [">=3.0.0 <6.5.4"],
            "engine.io-client": [">=3.0.0 <6.5.3"],
            "ws": [">=7.0.0 <7.5.6", ">=8.0.0 <8.1.1"],
            "jsonwebtoken": [">=8.0.0 <9.0.2"],
            "bcrypt": [">=1.0.0 <5.1.1"],
            "bcryptjs": [">=2.0.0 <2.4.3"],
            "passport": [">=0.1.0 <0.6.0"],
            "passport-jwt": [">=1.0.0 <4.0.1"],
            "passport-local": [">=1.0.0 <1.0.0"],
            "express-session": [">=1.0.0 <1.17.3"],
            "cookie-parser": [">=1.0.0 <1.4.6"],
            "body-parser": [">=1.0.0 <1.20.2"],
            "cors": [">=2.0.0 <2.8.5"],
            "helmet": [">=3.0.0 <7.1.0"],
            "rate-limiter-flexible": [">=1.0.0 <2.4.1"],
            "ioredis": [">=4.0.0 <5.3.2"],
            "redis": [">=3.0.0 <4.6.7"],
            "mongoose": [">=5.0.0 <7.6.3"],
            "typeorm": [">=0.2.0 <0.3.17"],
            "sequelize": [">=5.0.0 <6.35.0"],
            "prisma": [">=3.0.0 <5.6.0"],
            "graphql": [">=14.0.0 <16.8.1"],
            "apollo-server": [">=2.0.0 <3.12.0"],
            "apollo-client": [">=3.0.0 <3.8.0"],
            "urql": [">=1.0.0 <4.0.0"],
            "jest": [">=24.0.0 <29.7.0"],
            "vitest": [">=0.1.0 <1.0.0"],
            "cypress": [">=3.0.0 <13.6.0"],
            "playwright": [">=1.0.0 <1.40.0"],
            "@testing-library/react": [">=11.0.0 <14.0.0"],
            "@testing-library/jest-dom": [">=5.0.0 <6.1.0"],
            "@testing-library/user-event": [">=13.0.0 <14.5.0"],
            "storybook": [">=6.0.0 <7.6.0"],
            "esbuild": [">=0.1.0 <0.19.0"],
            "swc": [">=1.0.0 <1.3.0"],
            "parcel": [">=2.0.0 <2.10.0"],
            "snowpack": [">=3.0.0 <3.8.0"],
            "pnpm": [">=6.0.0 <8.10.0"],
            "yarn": [">=1.0.0 <1.22.19", ">=2.0.0 <4.0.0"],
            "npm": [">=6.0.0 <9.8.1", ">=9.8.1 <10.2.0"],
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
