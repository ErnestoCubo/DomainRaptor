# 🚀 Quick Start Guide

Get started with DomainRaptor in minutes! This guide will walk you through your first reconnaissance.

---

## 🎯 Your First Scan

### Basic Domain Discovery

Discover all assets for a domain:

```bash
domainraptor discover -T example.com
```

This will:

- Find subdomains from multiple sources
- Enumerate DNS records
- Discover SSL certificates
- Perform WHOIS lookup

### Understanding the Output

```
╭─────────────────── Scan Summary ───────────────────╮
│ Target: example.com                                │
│ Type: discover                                     │
│ Status: completed                                  │
│ Duration: 45.2s                                    │
│                                                    │
│ Findings:                                          │
│   • Assets: 24                                     │
│   • Services: 4                                    │
│   • Certificates: 12                               │
│   • Vulnerabilities: 0                             │
│   • Config Issues: 0                               │
╰────────────────────────────────────────────────────╯
```

---

## 📊 Common Workflows

### Workflow 1: Full Reconnaissance

Complete target assessment from discovery to reporting:

```bash
# Step 1: Discover assets
domainraptor discover -T example.com --subdomains --dns --ports --whois

# Step 2: Assess security configuration
domainraptor assess config example.com

# Step 3: Check for vulnerabilities
domainraptor assess vulns example.com

# Step 4: Generate report
domainraptor report generate example.com -f html -o example_report.html
```

### Workflow 2: Quick Security Check

Fast security posture assessment:

```bash
domainraptor -m quick assess config example.com
```

### Workflow 3: Deep Analysis

Thorough investigation with all sources:

```bash
domainraptor -m deep discover -T example.com --ports --recursive
```

### Workflow 4: Continuous Monitoring

Set up automated monitoring:

```bash
# Add target to watch list
domainraptor watch add example.com --interval 24h

# View monitored targets
domainraptor watch list

# Run checks manually
domainraptor watch run
```

---

## 🎛️ Global Options

These options work with any command:

| Option | Short | Description |
|--------|-------|-------------|
| `--version` | `-v` | Show version |
| `--verbose` | `-V` | Enable verbose output |
| `--debug` | | Enable debug mode |
| `--config` | `-c` | Custom config file |
| `--mode` | `-m` | Scan mode: quick, standard, deep, stealth |
| `--format` | `-f` | Output format: table, json, csv, yaml |
| `--output` | `-o` | Output file path |
| `--free-only` | | Use only free sources |
| `--no-color` | | Disable colored output |
| `--no-banner` | | Hide the banner |

### Examples

```bash
# JSON output to file
domainraptor -f json -o results.json discover -T example.com

# Quick mode without banner
domainraptor --no-banner -m quick discover -T example.com

# Deep scan with verbose output
domainraptor -V -m deep discover -T example.com

# Free sources only (no API keys needed)
domainraptor --free-only discover -T example.com
```

---

## 📁 Output Formats

### Table (Default)

Human-readable tables in the terminal:

```bash
domainraptor discover -T example.com
```

### JSON

Machine-readable format:

```bash
domainraptor -f json discover -T example.com
domainraptor -f json -o results.json discover -T example.com
```

### YAML

```bash
domainraptor -f yaml discover -T example.com
```

### CSV

```bash
domainraptor -f csv -o assets.csv discover -T example.com
```

---

## 💡 Tips for Effective Scanning

### 1. Start with Discovery

Always begin by discovering the attack surface:

```bash
domainraptor discover -T example.com
```

### 2. Use Appropriate Scan Mode

| Mode | Use Case | Speed |
|------|----------|-------|
| `quick` | Initial triage | Fast |
| `standard` | Regular assessments | Medium |
| `deep` | Thorough investigation | Slow |
| `stealth` | Low-profile scanning | Varies |

### 3. Save Results

Always save results to the database for comparison:

```bash
domainraptor discover -T example.com --save  # Default
```

### 4. Generate Reports

Create professional reports for stakeholders:

```bash
domainraptor report generate example.com -f html -o report.html --remediation
```

### 5. Monitor Changes

Set up monitoring for important targets:

```bash
domainraptor watch add example.com --interval 6h
```

---

## 🆘 Getting Help

### Command Help

```bash
# General help
domainraptor --help

# Command-specific help
domainraptor discover --help
domainraptor assess config --help
domainraptor report generate --help
```

### View Stored Data

```bash
# List all scans
domainraptor db list

# Show scan details
domainraptor db show 1

# Database statistics
domainraptor db stats
```

---

**← [Installation](Installation)** | **Next: [Configuration](Configuration) →**
