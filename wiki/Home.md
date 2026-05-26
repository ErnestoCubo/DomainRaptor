# 🦎 DomainRaptor Wiki

Welcome to the official DomainRaptor documentation! DomainRaptor is a powerful **Cyber Intelligence Tool** for domain reconnaissance and security assessment.

![Version](https://img.shields.io/badge/version-0.5.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-green)
![License](https://img.shields.io/badge/license-MIT-orange)

---

## 📚 Table of Contents

### Getting Started

- [Installation](Installation)
- [Quick Start Guide](Quick-Start)
- [Configuration](Configuration)

### Commands Reference

- [Discover Commands](Commands-Discover)
- [Recon Commands](Commands-Recon) — full ASM workflow (`recon fullscan`)
- [Assess Commands](Commands-Assess) — includes `assess exploits` (KEV / EPSS / Exploit-DB)
- [Enrich Commands](Commands-Enrich) — URLScan & 3rd-party intelligence
- [Report Commands](Commands-Report)
- [Watch Commands](Commands-Watch)
- [Compare Commands](Commands-Compare)
- [Database Commands](Commands-Database)

### Interfaces

- [Terminal UI (TUI)](TUI) — full-screen Textual app (`domainraptor tui`)

### Advanced

- [API Keys Setup](API-Keys)
- [Output Formats](Output-Formats)
- [Scan Modes](Scan-Modes)
- [Risk Algorithm](Risk-Algorithm) — how the 0-100 risk score is calculated
- [Examples & Use Cases](Examples)

---

## 🚀 What is DomainRaptor?

DomainRaptor is a comprehensive cyber intelligence tool designed for:

- **🔍 Domain Discovery** - Find subdomains, DNS records, and related assets
- **🛡️ Security Assessment** - Identify vulnerabilities and misconfigurations
- **📊 Reporting** - Generate detailed security reports in multiple formats
- **👁️ Monitoring** - Track changes in your attack surface over time
- **📈 Comparison** - Compare scan results and detect changes

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| Multi-source Discovery | Integrates with crt.sh, HackerTarget, Shodan, ZoomEye, Censys |
| Full ASM workflow | `recon fullscan` aggregates every source into one report |
| SSL/TLS Analysis | Deep certificate analysis and validation |
| DNS Security Checks | DNSSEC, SPF, DMARC, DKIM verification |
| HTTP Header Analysis | Security header compliance checking |
| Vulnerability Scanning | CVE database correlation (Shodan + NVD) |
| **Exploit Intelligence** | **CISA KEV, EPSS scores and Exploit-DB references** (no API key required) |
| 3rd-party enrichment | URLScan.io history and metadata |
| Multiple Output Formats | JSON, YAML, HTML, Markdown, PDF |
| Persistent Storage | SQLite database for scan history |
| Change Detection | Track modifications between scans |
| Risk Scoring | Weighted 0-100 score with KEV / EPSS bonuses ([details](Risk-Algorithm)) |
| Terminal UI | Full-screen interactive interface — `domainraptor tui` |

## 🎯 Quick Example

```bash
# 1. Build the attack surface (subdomains → IPs → services → CVEs)
domainraptor recon fullscan example.com

# 2. Enrich every CVE with CISA KEV / EPSS / Exploit-DB
domainraptor assess exploits example.com --save

# 3. Render a polished HTML report with KEV badges and exploit links
domainraptor report generate example.com -f html -o report.html

# Or launch the interactive TUI
domainraptor tui
```

## 📖 Getting Help

- **CLI Help**: Run `domainraptor --help` or `domainraptor <command> --help`
- **Issues**: [GitHub Issues](https://github.com/ErnestoCubo/DomainRaptor/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ErnestoCubo/DomainRaptor/discussions)

---

**Next**: [Installation Guide](Installation) →
