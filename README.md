# 🦖 DomainRaptor

![DomainRaptor](DomainRaptor.jpg)

[![Version](https://img.shields.io/github/v/release/ErnestoCubo/DomainRaptor?sort=semver)](https://github.com/ErnestoCubo/DomainRaptor/releases)
[![PyPI](https://img.shields.io/pypi/v/domainraptor)](https://pypi.org/project/domainraptor/)
[![CI](https://github.com/ErnestoCubo/DomainRaptor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ErnestoCubo/DomainRaptor/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ErnestoCubo/DomainRaptor/branch/main/graph/badge.svg)](https://codecov.io/gh/ErnestoCubo/DomainRaptor)
[![Python](https://img.shields.io/badge/python-3.10%2B-green)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange)](LICENSE)

**DomainRaptor** is a comprehensive **Cyber Intelligence & Attack Surface Management (ASM)** tool designed for red team operations, security assessments, and continuous monitoring. It aggregates data from multiple sources to provide deep visibility into an organization's external attack surface.

## 🎯 What is DomainRaptor?

DomainRaptor is built for security professionals who need to:

- **Discover** all external assets (subdomains, IPs, certificates, services)
- **Assess** security configurations and vulnerabilities
- **Enrich** findings with third-party threat intelligence
- **Monitor** changes in the attack surface over time
- **Report** findings in multiple formats for different audiences

## 🚀 Key Features

### 🔍 Multi-Source Discovery

| Source | Type | API key | Free tier |
|--------|------|---------|-----------|
| **crt.sh** | Certificate Transparency | ❌ | ✅ Unlimited |
| **CertSpotter** | Certificate Transparency | ❌ | ✅ Free |
| **HackerTarget** | Subdomain enumeration | ❌ | ✅ ~100/day |
| **Wayback Machine** | Historical subdomains / URLs | ❌ | ✅ Free |
| **WHOIS** | Registration metadata | ❌ | ✅ Free |
| **ASN lookup** | Network ownership | ❌ | ✅ Free |
| **NVD** | CVE database correlation | ⚠️ optional | ✅ Free |
| **Shodan** | Port / service / CVE data | ✅ | ⚠️ 100/month |
| **ZoomEye** | Subdomain discovery | ✅ | ✅ Subdomains free |
| **Censys** | IP lookup (Platform API v3) | ✅ PAT | ✅ Lookup free |

### 🛡️ Security Assessment

- SSL/TLS certificate analysis and validation (sslyze)
- DNS security checks (DNSSEC, SPF, DMARC, DKIM)
- HTTP security header compliance
- CVE correlation with CVSS scoring (NVD enrichment)
- Outdated-dependency / misconfiguration detection
- Weighted risk scoring across vulnerabilities, configuration, exposure and reputation

### 🔬 Third-Party Enrichment

- **VirusTotal** — domain / URL reputation and malware analysis
- **URLScan** — submitted-scan metadata for URLs
- **SecurityTrails** — historical DNS and WHOIS

### 📊 Reporting

- **HTML** — interactive dashboard with risk breakdown cards
- **JSON / YAML** — machine-readable for automation
- **Markdown** — documentation-friendly
- **PDF** — executive summaries

### 👁️ Continuous Monitoring

- Track changes between scans (`watch run`)
- Pause / resume / list watched targets
- Historical comparison with diff reports

### 🖥️ Terminal UI

- Full-featured [Textual](https://textual.textualize.io/) TUI launchable with `domainraptor tui`
- Interactive screens for discovery, assessment, comparison and scan history

## 📦 Installation

### From PyPI (recommended)

```bash
pip install domainraptor
# or, faster
uv pip install domainraptor
```

> First PyPI release is `v0.6.x`. If `pip install` returns 404, the publish workflow has not yet completed — fall back to the Git install below.

### From Git (latest development build)

```bash
pip install git+https://github.com/ErnestoCubo/DomainRaptor.git@main
```

### From source (for contributors)

```bash
git clone https://github.com/ErnestoCubo/DomainRaptor.git
cd DomainRaptor
uv sync --extra dev          # or: pip install -e ".[dev]"
```

## 🔧 Quick Start

### 1. Configure API Keys (optional but recommended)

```bash
# View available integrations
domainraptor config list

# Set API keys (stored in ~/.domainraptor/.env)
domainraptor config set SHODAN_API_KEY your-shodan-key
domainraptor config set ZOOMEYE_API_KEY your-zoomeye-key
domainraptor config set CENSYS_API_TOKEN censys_xxx_yyy
domainraptor config set VIRUSTOTAL_API_KEY your-vt-key

# Test configuration
domainraptor config test
```

### 2. Run Your First Scan

```bash
# Full reconnaissance scan
domainraptor recon fullscan example.com

# Quick subdomain discovery
domainraptor discover subdomains example.com

# Security assessment
domainraptor assess config example.com
```

### 3. Generate Reports

```bash
# HTML dashboard
domainraptor report generate example.com -f html -o report.html

# JSON for automation
domainraptor report generate example.com -f json -o data.json
```

### 4. Launch the TUI

```bash
domainraptor tui
```

## 📖 Command Reference

DomainRaptor groups its CLI into the following top-level commands:

| Group | Purpose |
|-------|---------|
| `discover` | Subdomain / certificate / host enumeration from individual sources |
| `recon` | High-level multi-source reconnaissance workflows |
| `assess` | Security assessments (SSL, DNS, headers, vulns, config) |
| `enrich` | Third-party intelligence enrichment |
| `watch` | Continuous monitoring of targets |
| `compare` | Diff scans / targets / history |
| `report` | Generate HTML / JSON / YAML / Markdown / PDF reports |
| `db` | Inspect, export and prune stored scans |
| `config` | Manage API keys and runtime settings |
| `tui` | Launch the Textual terminal UI |

### Discovery

```bash
domainraptor discover subdomains example.com           # multi-source enum
domainraptor discover certs example.com                # crt.sh + CertSpotter
domainraptor discover shodan-host 1.2.3.4
domainraptor discover zoomeye-subdomains example.com
domainraptor discover censys-host 1.2.3.4
domainraptor discover whois example.com
```

### Reconnaissance

```bash
domainraptor recon fullscan example.com
domainraptor recon fullscan example.com --no-shodan --no-censys
domainraptor recon fullscan example.com --max-results 50
```

### Assessment

```bash
domainraptor assess config example.com         # full posture check
domainraptor assess ssl example.com
domainraptor assess dns example.com
domainraptor assess headers https://example.com
domainraptor assess vulns example.com          # CVE correlation via NVD
domainraptor assess outdated example.com
domainraptor assess exploits example.com
```

### Enrichment

```bash
domainraptor enrich virustotal example.com
domainraptor enrich urlscan https://example.com
domainraptor enrich securitytrails example.com
```

### Monitoring

```bash
domainraptor watch add example.com --interval 24h
domainraptor watch list
domainraptor watch run                          # execute due checks once
domainraptor watch pause <id>
domainraptor watch resume <id>
domainraptor watch status <id>
domainraptor watch remove <id>
```

### Compare

```bash
domainraptor compare history example.com        # diff successive scans
domainraptor compare scans <id-a> <id-b>        # diff two scan ids
domainraptor compare targets example.com other.example.com
```

### Reports

```bash
domainraptor report generate example.com -f html -o report.html
domainraptor report generate example.com -f json -o data.json
domainraptor report list example.com
```

### Database

```bash
domainraptor db list                            # all stored scans
domainraptor db show <scan-id>
domainraptor db export <scan-id> -o scan.json
domainraptor db delete <scan-id>
```

## 🗂️ Project Structure

```
DomainRaptor/
├── src/domainraptor/
│   ├── cli/                 # Typer CLI commands
│   │   └── commands/        # discover, recon, assess, enrich, watch,
│   │                        # compare, report, db, config
│   ├── core/                # Configuration, models, risk scoring
│   ├── discovery/           # crt.sh, CertSpotter, HackerTarget, Wayback,
│   │                        # WHOIS, ASN, NVD, Shodan, ZoomEye, Censys
│   ├── assessment/          # SSL, DNS, headers, orchestrator
│   ├── enrichment/          # VirusTotal, URLScan, SecurityTrails
│   ├── reporting/           # HTML, JSON, YAML, Markdown, PDF generators
│   ├── storage/             # SQLite database + repositories
│   ├── tui/                 # Textual terminal UI
│   └── utils/               # Logging, output formatting
├── tests/                   # Pytest suite (unit + integration)
├── wiki/                    # Source of the GitHub Wiki
└── docs/                    # Additional documentation
```

## 🔐 API Keys & Free Tiers

| Service | Free tier | What you get |
|---------|-----------|--------------|
| **Shodan** | 100 queries/month | Port scanning, CVE lookup, banners |
| **ZoomEye** | Subdomain enum free | Subdomain enumeration (host search paid) |
| **Censys** | Direct lookup free | IP lookup via Platform API v3 (search paid) |
| **VirusTotal** | 500/day | Malware analysis, URL reputation |
| **SecurityTrails** | 50/month | Historical DNS, WHOIS |
| **URLScan** | Public scans free | Submitted scan metadata |
| **NVD** | Unlimited (rate-limited without key) | CVE / CVSS data |

> **Note**: core functionality (CT logs, HackerTarget, Wayback, WHOIS, ASN, DNS / SSL / header checks) works **without any API keys**.

## 🗺️ Roadmap

- [x] Multi-source subdomain discovery
- [x] Shodan integration with CVE enrichment
- [x] ZoomEye international API support
- [x] Censys Platform API v3 (PAT token)
- [x] HTML / JSON / YAML / Markdown / PDF reports
- [x] SQLite scan history
- [x] Weighted risk scoring algorithm
- [x] WHOIS lookup integration
- [x] Textual terminal UI
- [x] Continuous monitoring (`watch`)
- [ ] Active port scanning
- [ ] Nuclei template integration
- [ ] Slack / Discord notifications
- [ ] Docker container

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit using [Conventional Commits](https://www.conventionalcommits.org/) (`git commit -m 'feat: add amazing feature'`)
4. Push the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request against `develop`

The repository uses pre-commit hooks (`ruff`, `codespell`, `detect-secrets`). Run `uv run pre-commit install` after cloning. Releases are automated via [release-please](https://github.com/googleapis/release-please) and published to PyPI through OIDC trusted publishing.

## 📄 License

This project is open source under the [MIT License](LICENSE).

## ⚠️ Disclaimer

This tool is intended for **legal security research** and **authorized penetration testing only**. Users are responsible for ensuring they have proper authorization before scanning any targets. Unauthorized scanning may violate laws and service terms.

---

📚 **Documentation**: [Wiki](https://github.com/ErnestoCubo/DomainRaptor/wiki) | 🐛 **Issues**: [GitHub Issues](https://github.com/ErnestoCubo/DomainRaptor/issues) | 💬 **Discussions**: [GitHub Discussions](https://github.com/ErnestoCubo/DomainRaptor/discussions)
