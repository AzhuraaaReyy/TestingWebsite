# LocalGuard-Pro

**Internal Security Auditor CLI** untuk aplikasi web lokal/staging.

Mendeteksi kerentanan keamanan melalui Triple-Layer Audit:
- **DAST** (Dynamic Application Security Testing) - Runtime scanning
- **SAST** (Static Application Security Testing) - Source code analysis
- **SCA** (Software Composition Analysis) - Dependency vulnerability scanning

## 🎯 Target Stack

- **Frontend**: React TypeScript (Vite/Next.js)
- **Backend**: Laravel (PHP) / Supabase

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Git

### Installation

```bash
# Clone repository
git clone <repo-url>
cd LocalGuard-Pro

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Verify installation
localguard --help
```

### Usage

```bash
# Basic scan (local only)
localguard scan --target http://localhost:8000 --project-root .

# Scan with online CVE lookup
localguard scan --target http://localhost:8000 --project-root . --online-cve

# Custom config
localguard scan --target http://localhost:8000 --project-root . --config .localguard.yaml

# Generate report from existing JSON
localguard report --input security_report.json --format html

# Show config
localguard config show
```

### Exit Codes (CI/CD Ready)

| Code | Meaning |
|------|---------|
| 0 | Clean - No High/Critical findings |
| 1 | Vulnerabilities Found - Has High/Critical |
| 2 | Runtime Error - Config/Parse/System error |
| 3 | Blocked - Public domain rejected |

## 📁 Project Structure

```
LocalGuard-Pro/
├── localguard/              # Main package
│   ├── cli/                 # CLI commands (typer)
│   ├── core/                # Config, models, exceptions
│   ├── validation/          # Host validation & consent
│   ├── http/                # Rate-limited HTTP client & crawler
│   ├── auditors/            # Audit modules (DAST/SAST/SCA)
│   ├── reporting/           # Report generators
│   └── utils/               # Utilities (patterns, entropy)
├── tests/                   # Unit & integration tests
├── wordlists/               # Built-in wordlists
├── templates/               # HTML report template
├── scripts/                 # Utility scripts
└── docs/                    # Documentation
```

## ⚙️ Configuration

Copy `.localguard.yaml.example` to `.localguard.yaml` or `~/.config/localguard/localguard.yaml`:

```yaml
target:
  allowed_hosts:
    - "localhost"
    - "127.0.0.1"
    - "*.local"
    - "myapp.test"

scan:
  dast:
    max_depth: 2
    rate_limit_delay: 0.4
  sast:
    entropy_threshold: 4.5
  sca:
    online_cve: false
    ecosystems: ["composer", "npm"]

report:
  output_dir: "./security-reports"
  formats: ["json", "html", "terminal"]
  html_theme: "auto"
  title: "My App Security Audit"
  company_name: "My Company"
```

## 🔒 Security Features

- **Strict Local-Only Execution**: Blocks public domains automatically
- **Interactive Consent**: Requires explicit 'Y' before DAST scanning
- **Rate Limiting**: 0.3-0.5s delay between requests
- **Passive Analysis Only**: No active exploitation/payload injection
- **No Telemetry**: All data stays local

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=localguard --cov-report=html

# Run specific test types
pytest tests/unit/
pytest tests/integration/
```

## 📋 Requirements

### Runtime
- typer[all] >= 0.9.0
- rich >= 13.7.0
- pydantic >= 2.5.0
- pyyaml >= 6.0.1
- httpx >= 0.26.0
- beautifulsoup4 >= 4.12.0
- lxml >= 4.9.0
- jinja2 >= 3.1.0
- python-dotenv >= 1.0.0

### Development
- pytest >= 7.4.0
- pytest-asyncio >= 0.21.0
- pytest-cov >= 4.1.0
- ruff >= 0.1.0
- mypy >= 1.7.0
- black >= 23.0.0
- pre-commit >= 3.6.0

## 📄 License

MIT License - see LICENSE file

## ⚠️ Disclaimer

Tool ini hanya untuk pengujian keamanan **aplikasi milik sendiri** di lingkungan **lokal/staging**. Penggunaan terhadap target tanpa izin adalah **ilegal** dan melanggar etika keamanan siber.