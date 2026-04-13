# 📄 Report Commands

The `report` command generates comprehensive security reports in various formats.

---

## Overview

```bash
domainraptor report [OPTIONS] COMMAND [ARGS]
```

**Purpose:** Generate reports, export data, and schedule automated reporting.

---

## Commands

### `report generate`

Generate a comprehensive security report:

```bash
domainraptor report generate example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--output` | `-o` | Output file path | stdout |
| `--format` | `-f` | Format: json, yaml, html, md, pdf | `json` |
| `--history` | `-H` | Include scan history | `False` |
| `--remediation` | `-r` | Include remediation steps | `True` |
| `--scan` | `-s` | Specific scan ID to report | Latest |
| `--template` | `-t` | Custom report template | Default |

**Examples:**

```bash
# JSON report to stdout
domainraptor report generate example.com

# HTML report to file
domainraptor report generate example.com -f html -o report.html

# PDF report with history
domainraptor report generate example.com -f pdf -o report.pdf --history

# Markdown report with remediation
domainraptor report generate example.com -f md -o report.md --remediation

# YAML format
domainraptor report generate example.com -f yaml -o report.yaml

# Report for specific scan
domainraptor report generate example.com --scan abc123
```

**Supported Formats:**

| Format | Extension | Description | Use Case |
|--------|-----------|-------------|----------|
| `json` | .json | Machine-readable JSON | API integration, automation |
| `yaml` | .yaml | Human-readable YAML | Configuration, documentation |
| `html` | .html | Styled HTML report | Presentations, stakeholders |
| `md` | .md | Markdown document | Documentation, GitHub |
| `pdf` | .pdf | PDF document | Formal reports (requires wkhtmltopdf) |

---

## Vulnerability Details in Reports

Reports include comprehensive vulnerability information when available:

| Field | Description | Source |
|-------|-------------|--------|
| **CVE ID** | Unique vulnerability identifier | Shodan, NVD |
| **Severity** | CRITICAL, HIGH, MEDIUM, LOW | CVSS calculation |
| **CVSS Score** | Numerical vulnerability score (0-10) | NVD enrichment |
| **Affected Asset** | IP or hostname affected | Scan results |
| **Description** | Full vulnerability description | NVD API |
| **Remediation** | Recommended fix steps | Knowledge base |
| **Source** | Detection source (shodan, nmap, etc.) | Scan metadata |

**Example HTML Report (Vulnerability Section):**

```
┌─────────────────────────────────────────────────────────────────┐
│ Vulnerabilities (52 total)                                      │
├─────────────────────────────────────────────────────────────────┤
│ CVE-2022-3358 │ HIGH │ CVSS 7.5 │ 168.119.238.139               │
│ OpenSSL supports creating a custom cipher via the legacy        │
│ EVP_CIPHER_meth_new() function...                               │
├─────────────────────────────────────────────────────────────────┤
│ CVE-2023-2650 │ MEDIUM │ CVSS 6.5 │ 168.119.238.139             │
│ Processing some specially crafted ASN.1 object identifiers...   │
└─────────────────────────────────────────────────────────────────┘
```

> 💡 **Tip:** Use `domainraptor assess list <SCAN_ID> --enrich` before generating reports to fetch full CVE descriptions from NVD.

---

**Example HTML Report Structure:**

```
┌─────────────────────────────────────────────────────┐
│               Security Assessment Report            │
│                   example.com                       │
│             Generated: 2025-01-15 14:30             │
├─────────────────────────────────────────────────────┤
│ Executive Summary                                   │
│ ├── Risk Level: MEDIUM                              │
│ ├── Total Findings: 12                              │
│ └── Critical Issues: 0                              │
├─────────────────────────────────────────────────────┤
│ Discovered Assets                                   │
│ ├── Subdomains: 8                                   │
│ ├── IP Addresses: 3                                 │
│ ├── Services: 5                                     │
│ └── Certificates: 4                                 │
├─────────────────────────────────────────────────────┤
│ Security Findings                                   │
│ ├── Vulnerabilities: 0                              │
│ ├── Configuration Issues: 7                         │
│ └── Outdated Software: 2                            │
├─────────────────────────────────────────────────────┤
│ Remediation Steps                                   │
│ └── Prioritized action items...                     │
└─────────────────────────────────────────────────────┘
```

---

### `report summary`

Generate an executive summary:

```bash
domainraptor report summary example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--output` | `-o` | Output file path | stdout |
| `--format` | `-f` | Format: text, json, md | `text` |

**Examples:**

```bash
# Display summary in terminal
domainraptor report summary example.com

# Save as markdown
domainraptor report summary example.com -f md -o summary.md

# JSON format for processing
domainraptor report summary example.com -f json
```

**Example Output:**

```
╭────────────────── Executive Summary ──────────────────╮
│                                                       │
│ # Executive Summary: example.com                      │
│ Generated: 2025-01-15 14:30                           │
│                                                       │
│ ## Overview                                           │
│ Target analyzed with standard scan mode.              │
│                                                       │
│ ## Key Findings                                       │
│ - **Total Assets**: 24 discovered                     │
│ - **Critical Vulnerabilities**: 0                     │
│ - **High Vulnerabilities**: 2                         │
│ - **Configuration Issues**: 7                         │
│                                                       │
│ ## Risk Level: MEDIUM                                 │
│                                                       │
│ ## Recommendations                                    │
│ 1. Update TLS configuration to disable TLS 1.0       │
│ 2. Configure DNSSEC for domain                        │
│ 3. Add missing security headers                       │
│ 4. Implement DMARC with reject policy                 │
│                                                       │
│ ## Next Steps                                         │
│ - Schedule follow-up scan in 7 days                   │
│ - Review remediation progress                         │
│ - Update baseline after fixes                         │
│                                                       │
╰───────────────────────────────────────────────────────╯
```

---

### `report list`

List available reports and scans:

```bash
domainraptor report list
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--target` | `-t` | Filter by target | All |
| `--limit` | `-l` | Maximum results | 20 |
| `--type` | | Filter by scan type | All |

**Examples:**

```bash
# List all reports
domainraptor report list

# Filter by target
domainraptor report list --target example.com

# Show more results
domainraptor report list --limit 50

# Filter by type
domainraptor report list --type discover
```

**Example Output:**

```
ℹ Available reports:

                         Recent Scans
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Scan ID ┃ Target            ┃ Type          ┃ Date             ┃ Findings ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ abc123  │ example.com       │ discover      │ 2025-01-15 10:30 │ 24       │
│ def456  │ example.com       │ assess_config │ 2025-01-15 11:00 │ 7        │
│ ghi789  │ example.com       │ assess_vulns  │ 2025-01-15 11:15 │ 0        │
│ jkl012  │ test.example.org  │ discover      │ 2025-01-14 09:15 │ 18       │
│ mno345  │ api.example.com   │ discover      │ 2025-01-13 14:00 │ 5        │
└─────────┴───────────────────┴───────────────┴──────────────────┴──────────┘
```

---

### `report export`

Export raw scan data:

```bash
domainraptor report export example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--output` | `-o` | Output file path | stdout |
| `--format` | `-f` | Format: json, yaml, csv | `json` |
| `--scan` | `-s` | Specific scan ID | Latest |
| `--include` | | Data to include: assets, vulns, issues | All |

**Examples:**

```bash
# Export all data as JSON
domainraptor report export example.com -o data.json

# Export as CSV
domainraptor report export example.com -f csv -o data.csv

# Export only assets
domainraptor report export example.com --include assets -o assets.json

# Export specific scan
domainraptor report export example.com --scan abc123 -o scan_data.json
```

---

### `report schedule`

Schedule automated reports (creates cron job or scheduled task):

```bash
domainraptor report schedule example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--interval` | `-i` | Report interval: daily, weekly, monthly | `weekly` |
| `--format` | `-f` | Report format | `html` |
| `--output` | `-o` | Output directory | `~/.domainraptor/reports` |
| `--email` | `-e` | Send report via email | None |
| `--webhook` | `-w` | Send to webhook URL | None |

**Examples:**

```bash
# Weekly HTML report
domainraptor report schedule example.com --interval weekly -f html

# Daily JSON report to specific directory
domainraptor report schedule example.com --interval daily -f json -o /var/reports/

# Weekly report with email notification
domainraptor report schedule example.com --email security@example.com

# Daily report to webhook
domainraptor report schedule example.com --interval daily --webhook https://hooks.slack.com/xxx
```

**Example Output:**

```
ℹ Scheduling report for: example.com

Report Schedule Configuration:
  Target: example.com
  Interval: weekly
  Format: html
  Output: ~/.domainraptor/reports/example.com/
  Next Run: 2025-01-22 00:00

✓ Report scheduled successfully
ℹ Cron entry created: 0 0 * * 0 domainraptor report generate...
```

---

## Report Templates

### Using Custom Templates

```bash
domainraptor report generate example.com --template executive
domainraptor report generate example.com --template technical
domainraptor report generate example.com --template compliance
```

### Available Templates

| Template | Description |
|----------|-------------|
| `default` | Standard comprehensive report |
| `executive` | High-level summary for management |
| `technical` | Detailed technical findings |
| `compliance` | Compliance-focused report |
| `minimal` | Brief summary only |

---

## Integrating Reports

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Generate Security Report
  run: |
    domainraptor assess config example.com
    domainraptor report generate example.com -f json -o report.json

- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: security-report
    path: report.json
```

### Slack/Webhook Integration

```bash
# Generate and send to Slack
domainraptor report summary example.com -f json | \
  curl -X POST -H 'Content-type: application/json' \
  --data @- https://hooks.slack.com/services/xxx/yyy/zzz
```

### Email Reports

```bash
# Generate and email (using mail command)
domainraptor report generate example.com -f html -o report.html
mail -s "Security Report" -a report.html security@example.com < /dev/null
```

---

## Best Practices

1. **Regular Reporting**: Schedule weekly reports for ongoing monitoring
2. **Multiple Formats**: Generate HTML for stakeholders, JSON for automation
3. **Include Remediation**: Always include remediation steps for actionable reports
4. **Historical Context**: Use `--history` flag to show trends
5. **Secure Storage**: Store reports in secure, access-controlled locations

---

**← [Assess Commands](Commands-Assess)** | **Next: [Watch Commands](Commands-Watch) →**
