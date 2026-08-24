# LocalGuard-Pro Design Specification

**Version:** 1.1.0  
**Date:** 2026-08-24  
**Author:** DevSecOps Architect & Senior Penetration Tester  
**Status:** Approved - Ready for Implementation  

---

## 1. Executive Summary

LocalGuard-Pro adalah **internal security auditor CLI** berbasis Python 3.10+ yang dirancang untuk mendeteksi kerentanan keamanan secara mendalam pada aplikasi web milik sendiri di lingkungan lokal/staging sebelum deploy ke produksi.

**Target Stack:** React TypeScript (Frontend) + Laravel/Supabase (Backend)  
**Arsitektur:** Modular Monolith dengan OOP Layered pattern  
**Scope:** DAST (Dynamic), SAST (Static), SCA (Dependencies) - Triple-Layer Audit

---

## 2. Core Requirements

### 2.1 Strict Local Execution Guard (Anti-Abuse)

| Requirement | Specification |
|-------------|---------------|
| **Host Validation** | Allowlist ketat: `localhost`, `127.0.0.1`, `0.0.0.0`, IP Privat (192.168.x.x, 10.x.x.x, 172.16-31.x.x), TLD `.local`, `.test` |
| **Hard Block** | `sys.exit(3)` dengan legal warning jika target domain publik (Exit Code 3 = Blocked) |
| **Interactive Consent** | Prompt konfirmasi `Y` eksplisit sebelum scan DAST dimulai |
| **Rate Limiting** | Delay dinamis 0.3-0.5s antar request (configurable) |

### 2.2 Triple-Layer Audit Modules

#### Layer 1: DAST (Dynamic Application Security Testing)

| Auditor | Class | Key Checks |
|---------|-------|------------|
| Header & Cookie Security | `HeaderCookieAuditor` | 6 security headers, cookie flags (HttpOnly, Secure, SameSite), version disclosure |
| Sensitive File & Endpoint Scanner | `SensitivePathScanner` | Wordlist-based scan (.env, .git, backups, debug endpoints, Laravel-specific paths, React Source Maps) |
| Form & Injection Analyzer | `FormInjectionAuditor` | Form crawl, CSRF token detection, passive XSS/SQLi indicator analysis (safe mode) |
| Access Control & Auth Bypass | `AccessControlAuditor` | Auth bypass testing, IDOR detection, Laravel Sanctum middleware protection verification |
| CORS Security Auditor | `CORSAuditor` | **NEW** - CORS misconfiguration: `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` detection |

#### Layer 2: SAST (Static Application Security Testing)

| Component | `SecretScanner` |
|-----------|-----------------|
| **Target** | Source code lokal (exclude: node_modules, vendor, .git, dist, build, venv, __pycache__) |
| **Technique** | Regex pattern matching + Shannon entropy analysis (>4.5 for strings >20 chars) |
| **Patterns** | AWS keys, generic API keys, private keys, JWT, DB URLs, Laravel APP_KEY/DB_PASSWORD, Supabase keys (classified) |
| **FP Reduction** | Entropy filter, `.localguard-ignore` allowlist, context-aware (skip tests/examples/docs) |
| **Supabase Key Classification** | **NEW** - Dedicated regex: `eyJ...` (Anon Key = Low) vs `eyJ...` with service_role claims (Service Role Key = Critical) |
| **Laravel .env.example Check** | **NEW** - Detect committed secrets in `.env.example`, `.env.local`, `.env.production` |

#### Layer 3: SCA (Software Composition Analysis)

| Mode | Detail |
|------|--------|
| **Offline (Default)** | Parse `composer.lock`, `package-lock.json`/`yarn.lock`, `requirements.txt`; heuristic version comparison vs embedded CVE database (~500 top CVE); flag deprecated/unmaintained/loose version constraints |
| **Online (Optional `--online-cve`)** | Query OSV.dev API (free, no key), GitHub Advisory, NVD; 24h local cache; respectful rate limiting |
| **Ecosystems** | Composer (PHP/Laravel), npm/yarn/pnpm (React TS), pip/poetry (Python) |

### 2.3 Interface, Monitoring & Reporting

| Feature | Implementation |
|---------|----------------|
| **CLI Framework** | `typer` + `rich` (type-safe, auto-completion, beautiful terminal) |
| **Commands** | `scan`, `report`, `config`, `ignore` |
| **Progress** | `rich.progress.Progress` per auditor + overall |
| **Color Coding** | Critical/High=red, Medium=yellow, Low=green, Info=blue |
| **Terminal Summary** | Executive summary: stats by severity, top 5 critical, duration |
| **JSON Report** | `security_report.json` - CI/CD ready, SIEM ingestible |
| **HTML Report** | `security_report.html` - Bootstrap 5 CDN, collapsible, filterable, searchable, dark mode, print-friendly, **custom branding via config** |

### 2.4 Finding Schema (Standardized)

```json
{
  "id": "LG-DAST-HEADER-001",
  "severity": "Critical|High|Medium|Low|Info",
  "category": "DAST|SAST|SCA",
  "title": "Human-readable title",
  "endpoint": "https://localhost:8000/api/users/1",
  "parameter": "id",
  "evidence": "Technical evidence",
  "impact": "Business/technical impact",
  "remediation": "Specific fix with code example",
  "cwe": "CWE-XXX",
  "owasp": "A0X:2021 - Category",
  "references": ["https://..."]
}
```

### 2.5 Exit Codes (Standardized for CI/CD)

| Code | Name | Description |
|------|------|-------------|
| **0** | `CLEAN` | Tidak ada temuan High/Critical |
| **1** | `VULNERABILITIES_FOUND` | Terdapat minimal 1 temuan High/Critical |
| **2** | `RUNTIME_ERROR` | Gagal parse config / file corrupt / system error |
| **3** | `BLOCKED` | Target domain publik ditolak oleh HostValidationEngine |

---

## 3. Architecture Design

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI Entry Point                        │
│                    (typer + rich)                           │
└─────────────────────────┬───────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  Scan Orchestrator                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   DAST      │  │   SAST      │  │   SCA       │         │
│  │ Orchestrator│  │ Orchestrator│  │ Orchestrator│         │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘         │
└─────────┼────────────────┼────────────────┼─────────────────┘
          ▼                ▼                ▼
   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
   │ 5 Auditors  │  │ 1 Scanner   │  │ 1 Scanner   │
   │ (parallel)  │  │ (sequential)│  │ (parallel)  │
   └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
          ▼                ▼                ▼
   ┌─────────────────────────────────────────────┐
   │           Finding Aggregator                │
   │      (dedup, severity sort, enrich)         │
   └────────────────────┬────────────────────────┘
                        ▼
   ┌─────────────────────────────────────────────┐
   │         Report Generator                    │
   │  ┌─────────┐ ┌─────────┐ ┌─────────────┐   │
   │  │Terminal │ │  JSON   │ │    HTML     │   │
   │  └─────────┘ └─────────┘ └─────────────┘   │
   └─────────────────────────────────────────────┘
```

### 3.2 Core Class Hierarchy

```
BaseAuditor (ABC)
    ├── DASTAuditor (ABC)
    │   ├── HeaderCookieAuditor
    │   ├── SensitivePathScanner
    │   ├── FormInjectionAuditor
    │   ├── AccessControlAuditor
    │   └── CORSAuditor                    # NEW
    ├── SASTAuditor (ABC)
    │   └── SecretScanner
    └── SCAAuditor (ABC)
        └── DependencyScanner
            ├── ComposerParser
            ├── NPMParser
            ├── PipParser
            ├── OfflineCVESource
            └── OSVCVESource
```

### 3.3 Data Flow

1. **Input Validation** → `HostValidationEngine.validate(target_url)` → raises `ValidationError` if blocked (exit code 3)
2. **Consent** → `ConsentManager.request()` → returns `bool` (must be True)
3. **Target Creation** → `Target(url, project_root, config)` dataclass
4. **Parallel DAST** → Each auditor runs independently with shared `RateLimitedHTTPClient`
5. **Sequential SAST** → `SecretScanner.scan(project_root)` → file-by-file
6. **Parallel SCA** → Each ecosystem parser runs, then CVE sources queried
7. **Aggregation** → `FindingAggregator.merge(all_findings)` → dedup by (location, type)
8. **Reporting** → `ReportGenerator.generate(findings, config)` → multi-format output
9. **Exit Code Determination** → Based on highest severity finding (0/1/2/3)

---

## 4. Project Structure

```
LocalGuard-Pro/
├── .github/workflows/ci.yml
├── .vscode/{settings.json,launch.json,extensions.json}
├── docs/{architecture.md,usage.md,contributing.md}
├── localguard/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli/
│   │   ├── app.py
│   │   ├── commands/{scan.py,report.py,config.py}
│   │   └── console.py
│   ├── core/
│   │   ├── config.py (Pydantic Settings)
│   │   ├── models.py (Finding, Target, ScanResult)
│   │   ├── exceptions.py
│   │   └── constants.py
│   ├── validation/
│   │   ├── host_validator.py
│   │   └── consent.py
│   ├── http/
│   │   ├── client.py (RateLimitedHTTPClient)
│   │   └── crawler.py (BFSCrawler)
│   ├── auditors/
│   │   ├── base.py
│   │   ├── dast/
│   │   │   ├── header_cookie.py
│   │   │   ├── sensitive_paths.py
│   │   │   ├── forms_injection.py
│   │   │   ├── access_control.py
│   │   │   └── cors.py                 # NEW
│   │   ├── sast/
│   │   │   └── secrets.py
│   │   └── sca/
│   │       ├── scanner.py
│   │       ├── parsers/{composer.py,npm.py,pip.py}
│   │       └── sources/{offline.py,osv.py}
│   ├── reporting/
│   │   ├── generator.py
│   │   ├── terminal.py
│   │   ├── json_report.py
│   │   └── html_report.py
│   └── utils/{patterns.py,entropy.py,filesystem.py}
├── tests/
│   ├── unit/{test_host_validator.py,test_secret_scanner.py,test_dependency_parser.py,test_finding_models.py,test_cors_auditor.py}
│   ├── integration/{test_dast_auditors.py,test_full_scan.py}
│   └── fixtures/{sample_composer.lock,sample_package-lock.json,vulnerable_code_samples/}
├── scripts/{install.sh,dev-setup.sh}
├── wordlists/{sensitive_paths.txt,laravel_paths.txt,react_paths.txt}  # NEW react_paths.txt
├── templates/report.html.j2
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── localguard.yaml (bundled default)
├── .localguard.yaml.example
├── .gitignore
├── .pre-commit-config.yaml
├── README.md
├── LICENSE
└── CHANGELOG.md
```

---

## 5. Configuration System

### 5.1 Configuration Precedence (High to Low)

1. CLI arguments (`--target`, `--online-cve`, `--output-dir`, etc.)
2. User config file (`~/.config/localguard/localguard.yaml`)
3. Project config file (`.localguard.yaml` in project root)
4. Bundled default (`localguard.yaml` in package)

### 5.2 Config Schema (Pydantic) - UPDATED

```yaml
target:
  allowed_hosts: ["localhost", "127.0.0.1", "0.0.0.0", "*.local", "*.test"]
  custom_private_ranges: []

scan:
  dast:
    max_depth: 2
    rate_limit_delay: 0.4
    timeout: 10
    follow_redirects: true
    custom_wordlist: null                    # Path to custom wordlist file (merged with built-in)
  sast:
    exclude_patterns: ["**/node_modules/**", "**/vendor/**", "**/.git/**", "**/dist/**", "**/build/**", "**/venv/**", "**/__pycache__/**"]
    entropy_threshold: 4.5
    custom_patterns: []
  sca:
    online_cve: false
    cache_ttl_hours: 24
    ecosystems: ["composer", "npm"]

report:
  output_dir: "./security-reports"
  formats: ["json", "html", "terminal"]
  html_theme: "auto"
  title: "LocalGuard-Pro Security Audit Report"     # NEW - Custom report title
  company_name: ""                                  # NEW - Company branding

ignore:
  paths: []
  patterns: []
  findings: []
```

---

## 6. Technical Specifications

### 6.1 Dependencies (requirements.txt)

```text
# Core
typer[all]>=0.9.0
rich>=13.7.0
pydantic>=2.5.0
pyyaml>=6.0.1

# HTTP & Crawling
httpx>=0.26.0
beautifulsoup4>=4.12.0
lxml>=4.9.0

# Templating
jinja2>=3.1.0

# Utilities
python-dotenv>=1.0.0
```

### 6.2 Dev Dependencies (requirements-dev.txt)

```text
pytest>=7.4.0
pytest-asyncio>=0.21.0
pytest-cov>=4.1.0
pytest-mock>=3.12.0
ruff>=0.1.0
mypy>=1.7.0
black>=23.0.0
pre-commit>=3.6.0
```

### 6.3 Python Version & Packaging

- **Python:** >=3.10 (typing: `Self`, `TypeAlias`, `dataclass_transform`)
- **Packaging:** `pyproject.toml` (PEP 621) with `hatchling` build backend
- **Entry Point:** `localguard = localguard.cli.app:app`

---

## 7. Security Considerations

### 7.1 Anti-Abuse Measures (Mandatory)

1. **Host Validation Engine** - Runs FIRST before any network activity
2. **No External Calls Without Consent** - DAST only executes after interactive `Y`
3. **Rate Limiting** - Enforced at HTTP client level (token bucket)
4. **No Active Exploitation** - DAST is passive analysis only (no payload injection)
5. **Local-Only SCA** - Offline mode default; online requires explicit flag

### 7.2 Safe Defaults

- `max_depth: 2` for crawler
- `timeout: 10s` for HTTP requests
- `follow_redirects: true` but max 5 redirects
- Exclude sensitive dirs by default in SAST

### 7.3 Data Handling

- No telemetry, no phone-home
- Reports written locally only
- CVE cache stored in `~/.cache/localguard/`
- No secrets logged (redacted in evidence)

---

## 8. Testing Strategy

### 8.1 Unit Tests (Target: >90% coverage)

| Module | Test Focus |
|--------|------------|
| `HostValidator` | Allowlist/blocklist, IPv4/IPv6, CIDR, TLD edge cases |
| `SecretScanner` | Regex accuracy, entropy calc, false positive reduction, Supabase key classification |
| `DependencyParser` | Lock file parsing accuracy per ecosystem |
| `Finding Models` | Serialization, severity ordering, equality |
| `CORSAuditor` | CORS header combination analysis |

### 8.2 Integration Tests

| Test | Description |
|------|-------------|
| `test_dast_auditors.py` | Spin up test Flask/Laravel app, run DAST against it |
| `test_full_scan.py` | End-to-end scan with all layers, verify report outputs |

### 8.3 Test Fixtures

- `sample_composer.lock` - Laravel 10 with known vulnerable packages
- `sample_package-lock.json` - React 18 with vulnerable deps
- `vulnerable_code_samples/` - PHP/JS/TS files with seeded secrets/vulns (including Supabase keys, Laravel .env.example)

---

## 9. CI/CD Pipeline (.github/workflows/ci.yml)

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - ruff check .
      - mypy localguard/
      - black --check .
  
  test:
    runs-on: ubuntu-latest
    steps:
      - pytest --cov=localguard --cov-fail-under=90
  
  build:
    needs: [lint, test]
    runs-on: ubuntu-latest
    steps:
      - pipx run build
      - twine check dist/*
```

---

## 10. VS Code Integration

### 10.1 Launch Configurations (`.vscode/launch.json`)

```json
{
  "configurations": [
    {
      "name": "LocalGuard: Scan Local",
      "type": "python",
      "request": "launch",
      "module": "localguard",
      "args": ["scan", "--target", "http://localhost:8000", "--project-root", "${workspaceFolder}"],
      "console": "integratedTerminal"
    },
    {
      "name": "LocalGuard: Debug Tests",
      "type": "python",
      "request": "launch",
      "module": "pytest",
      "args": ["tests/", "-v"],
      "console": "integratedTerminal"
    }
  ]
}
```

### 10.2 Recommended Extensions (`.vscode/extensions.json`)

```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.black-formatter",
    "charliermarsh.ruff",
    "ms-python.mypy-type-checker"
  ]
}
```

---

## 11. Implementation Phases

| Phase | Deliverable | Est. Effort |
|-------|-------------|-------------|
| **Phase 1** | Project scaffolding, config system, host validation, consent, HTTP client | 2-3 days |
| **Phase 2** | DAST auditors (5 modules incl. CORS) + crawler | 3-4 days |
| **Phase 3** | SAST SecretScanner + entropy + ignore system + Supabase classification | 2-3 days |
| **Phase 4** | SCA DependencyScanner + parsers (composer, npm, pip) + offline CVE | 3 days |
| **Phase 5** | Reporting (terminal, JSON, HTML with Bootstrap 5 + branding) | 2 days |
| **Phase 6** | CLI polish, config file, docs, tests, CI | 2-3 days |
| **Total** | **MVP Ready** | **~14-18 days** |

---

## 12. Future Extensibility (Post-MVP)

- Plugin system for custom auditors
- SARIF output for GitHub Code Scanning
- GitHub Actions / GitLab CI integration
- Web dashboard for historical scan comparison
- Custom rule engine (YARA-like for SAST)
- Authentication testing (login flow, session handling)
- Supabase RLS policy analyzer

---

## 13. Decisions Log (Resolved Open Questions)

| # | Question | Decision | Rationale |
|---|----------|----------|-----------|
| 1 | Wordlist Customization | **Allow merge**: Built-in + custom via `scan.dast.custom_wordlist` | Flexibility without losing curated defaults |
| 2 | Supabase Specific Checks | **Add dedicated module**: Anon vs Service Role key classification + RLS endpoint scan | Critical risk differentiation for Supabase stack |
| 3 | Laravel Sanctum Testing | **Surface-level**: Auth bypass + middleware protection on `/api/*` | MVP scope; deep token analysis post-MVP |
| 4 | HTML Report Customization | **Add `report.title` & `report.company_name`** | Branding for enterprise/internal distribution |
| 5 | Exit Codes | **Standardized 0/1/2/3** (see Section 2.5) | CI/CD pipeline compatibility |

---

## 14. Approval

**Spec Review Checklist:**

- [x] Placeholder scan: No TBD/TODO remaining
- [x] Internal consistency: Architecture matches module descriptions
- [x] Scope check: Single implementation plan feasible
- [x] Ambiguity check: All requirements explicitly defined

**Reviewer:** ________________  
**Date:** ________________  
**Decision:** [x] Approved  [ ] Changes Requested