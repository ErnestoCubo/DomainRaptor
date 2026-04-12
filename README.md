# 🦖 DomainRaptor

![DomainRaptor](DomainRaptor.jpg)

[![Version](https://img.shields.io/badge/version-0.3.0-blue)](https://github.com/ErnestoCubo/DomainRaptor/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-green)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-orange)](LICENSE)

**DomainRaptor** is a comprehensive **Cyber Intelligence & Attack Surface Management (ASM)** tool designed for red team operations, security assessments, and continuous monitoring. It aggregates data from multiple sources to provide deep visibility into an organization's external attack surface.

## 🎯 What is DomainRaptor?

DomainRaptor is built for security professionals who need to:

- **Discover** all external assets (subdomains, IPs, certificates, services)
- **Assess** security configurations and vulnerabilities
- **Monitor** changes in the attack surface over time
- **Report** findings in multiple formats for different audiences

## 🚀 Key Features

### 🔍 Multi-Source Discovery

| Source | Type | Free Tier |
|--------|------|-----------|
| **crt.sh** | Certificate Transparency | ✅ Unlimited |
| **HackerTarget** | Subdomain enumeration | ✅ 100/day |
| **Shodan** | Port/service/CVE data | ✅ 100/month |
| **ZoomEye** | Subdomain discovery | ✅ Free |
| **Censys** | IP lookup | ✅ Free |

### 🛡️ Security Assessment

- SSL/TLS certificate analysis and validation
- DNS security checks (DNSSEC, SPF, DMARC, DKIM)
- HTTP security header compliance
- CVE correlation with CVSS scoring
- Risk calculation based on exposure

### 📊 Reporting

- **HTML** - Interactive dashboard with charts
- **JSON/YAML** - Machine-readable for automation
- **Markdown** - Documentation-friendly
- **PDF** - Executive summaries

### 👁️ Continuous Monitoring

- Track changes between scans
- Alert on new assets or vulnerabilities
- Historical comparison with diff reports

## 📦 Installation

### Using pip (recommended)

```bash
pip install domainraptor
```

### From source

```bash
git clone https://github.com/ErnestoCubo/DomainRaptor.git
cd DomainRaptor
pip install -e .
```

### Using uv (fastest)

```bash
uv pip install domainraptor
```

## 🔧 Quick Start

### 1. Configure API Keys (optional but recommended)

```bash
# View available integrations
domainraptor config list

# Set API keys
domainraptor config set SHODAN_API_KEY your-shodan-key
domainraptor config set ZOOMEYE_API_KEY your-zoomeye-key
domainraptor config set CENSYS_API_TOKEN censys_xxx_yyy

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

## 📖 Command Reference

### Discovery Commands

```bash
# Subdomain enumeration from multiple sources
domainraptor discover subdomains example.com

# Shodan host enrichment
domainraptor discover shodan-host 1.2.3.4

# ZoomEye subdomain search (free)
domainraptor discover zoomeye-subdomains example.com

# Censys IP lookup (free)
domainraptor discover censys-host 1.2.3.4

# Certificate search
domainraptor discover certs example.com
```

### Reconnaissance Commands

```bash
# Full attack surface scan
domainraptor recon fullscan example.com

# With specific sources
domainraptor recon fullscan example.com --no-shodan --no-censys

# Limit results
domainraptor recon fullscan example.com --max-results 50
```

### Assessment Commands

```bash
# Full security assessment
domainraptor assess config example.com

# SSL/TLS analysis
domainraptor assess ssl example.com

# DNS security check
domainraptor assess dns example.com
```

### Report Commands

```bash
# Generate HTML report
domainraptor report generate example.com -f html

# List available scans
domainraptor report list example.com

# Compare two scans
domainraptor compare scans 1 2
```

### Monitoring Commands

```bash
# Watch for changes (runs periodically)
domainraptor watch start example.com --interval 24h

# List active watchers
domainraptor watch list
```

## 🗂️ Project Structure

```
DomainRaptor/
├── src/domainraptor/
│   ├── cli/                 # Typer CLI commands
│   │   └── commands/        # discover, assess, report, recon, watch
│   ├── core/                # Configuration and models
│   ├── discovery/           # API clients (Shodan, ZoomEye, Censys, etc.)
│   ├── assessment/          # Security checks (SSL, DNS, headers)
│   ├── enrichment/          # VirusTotal, WHOIS, etc.
│   ├── reporting/           # HTML, JSON, PDF generators
│   ├── storage/             # SQLite database layer
│   └── utils/               # Logging, output formatting
├── tests/                   # Pytest test suite
├── wiki/                    # Documentation (GitHub Wiki)
└── docs/                    # Additional documentation
```

## 🔐 API Keys & Free Tiers

| Service | Free Tier | What You Get |
|---------|-----------|--------------|
| **Shodan** | 100/month | Port scanning, CVE lookup, banners |
| **ZoomEye** | Subdomain free | Subdomain enumeration (host search paid) |
| **Censys** | IP lookup free | Direct IP lookup (search paid) |
| **VirusTotal** | 500/day | Malware analysis, URL reputation |

> **Note**: Basic functionality works without API keys using crt.sh and HackerTarget.

## 🗺️ Roadmap

- [x] Multi-source subdomain discovery
- [x] Shodan integration with CVE enrichment
- [x] ZoomEye international API support
- [x] Censys Platform API v3 (PAT token)
- [x] HTML/JSON/YAML reports
- [x] SQLite scan history
- [x] Risk scoring algorithm
- [ ] WHOIS lookup integration
- [ ] Active port scanning
- [ ] Nuclei template integration
- [ ] Slack/Discord notifications
- [ ] Docker container

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is open source under the [MIT License](LICENSE).

## ⚠️ Disclaimer

This tool is intended for **legal security research** and **authorized penetration testing only**. Users are responsible for ensuring they have proper authorization before scanning any targets. Unauthorized scanning may violate laws and service terms.

---

📚 **Documentation**: [Wiki](https://github.com/ErnestoCubo/DomainRaptor/wiki) | 🐛 **Issues**: [GitHub Issues](https://github.com/ErnestoCubo/DomainRaptor/issues) | 💬 **Discussions**: [GitHub Discussions](https://github.com/ErnestoCubo/DomainRaptor/discussions)
