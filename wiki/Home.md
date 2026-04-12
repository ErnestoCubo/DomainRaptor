# 🦎 DomainRaptor Wiki

Welcome to the official DomainRaptor documentation! DomainRaptor is a powerful **Cyber Intelligence Tool** for domain reconnaissance and security assessment.

![Version](https://img.shields.io/badge/version-0.3.0-blue)
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
- [Assess Commands](Commands-Assess)
- [Report Commands](Commands-Report)
- [Watch Commands](Commands-Watch)
- [Compare Commands](Commands-Compare)
- [Database Commands](Commands-Database)

### Advanced

- [API Keys Setup](API-Keys)
- [Output Formats](Output-Formats)
- [Scan Modes](Scan-Modes)
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
| SSL/TLS Analysis | Deep certificate analysis and validation |
| DNS Security Checks | DNSSEC, SPF, DMARC, DKIM verification |
| HTTP Header Analysis | Security header compliance checking |
| Vulnerability Scanning | CVE database correlation |
| Multiple Output Formats | JSON, YAML, HTML, Markdown, PDF |
| Persistent Storage | SQLite database for scan history |
| Change Detection | Track modifications between scans |
| Risk Scoring | Algorithmic risk calculation based on exposure |

## 🎯 Quick Example

```bash
# Discover all assets for a domain
domainraptor discover -T example.com --subdomains --dns --ports

# Assess security configuration
domainraptor assess config example.com

# Generate an HTML report
domainraptor report generate example.com -f html -o report.html
```

## 📖 Getting Help

- **CLI Help**: Run `domainraptor --help` or `domainraptor <command> --help`
- **Issues**: [GitHub Issues](https://github.com/ErnestoCubo/DomainRaptor/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ErnestoCubo/DomainRaptor/discussions)

---

**Next**: [Installation Guide](Installation) →
