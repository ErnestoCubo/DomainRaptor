# 📤 Output Formats

DomainRaptor supports multiple output formats for different use cases.

---

## Available Formats

| Format | Extension | Use Case |
|--------|-----------|----------|
| `table` | - | Terminal display (default) |
| `json` | .json | API integration, automation |
| `yaml` | .yaml | Human-readable, configuration |
| `csv` | .csv | Spreadsheets, Excel |
| `html` | .html | Reports, presentations |
| `md` | .md | Documentation, GitHub |
| `pdf` | .pdf | Formal reports |

---

## Setting Output Format

### Command Line

```bash
# Global option
domainraptor -f json discover -T example.com
domainraptor --format yaml discover -T example.com

# With output file
domainraptor -f json -o results.json discover -T example.com
domainraptor --format html --output report.html report generate example.com
```

### Configuration File

```yaml
# ~/.domainraptor/config.yaml
output:
  format: json  # Default format
```

---

## Format Details

### Table (Default)

Best for: Terminal viewing, quick analysis

```bash
domainraptor discover -T example.com
# or
domainraptor -f table discover -T example.com
```

**Example:**

```
                     Discovered Assets
┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Type      ┃ Value                    ┃ Source        ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ ip        │ 93.184.216.34            │ dns           │
│ subdomain │ www.example.com          │ crt_sh        │
│ subdomain │ mail.example.com         │ hackertarget  │
│ subdomain │ api.example.com          │ shodan        │
└───────────┴──────────────────────────┴───────────────┘
```

---

### JSON

Best for: Automation, API integration, scripting

```bash
domainraptor -f json discover -T example.com
domainraptor -f json -o results.json discover -T example.com
```

**Example:**

```json
{
  "scan_id": "abc123",
  "target": "example.com",
  "type": "discover",
  "status": "completed",
  "timestamp": "2025-01-15T10:30:00Z",
  "duration_seconds": 45.2,
  "summary": {
    "assets": 24,
    "services": 5,
    "certificates": 8,
    "vulnerabilities": 0,
    "config_issues": 7
  },
  "assets": [
    {
      "type": "ip",
      "value": "93.184.216.34",
      "source": "dns",
      "first_seen": "2025-01-15T10:30:05Z",
      "metadata": {}
    },
    {
      "type": "subdomain",
      "value": "www.example.com",
      "source": "crt_sh",
      "first_seen": "2025-01-15T10:30:10Z",
      "metadata": {
        "ip": "93.184.216.34"
      }
    }
  ],
  "services": [],
  "certificates": [],
  "vulnerabilities": [],
  "config_issues": []
}
```

**Processing with jq:**

```bash
# Extract subdomains only
domainraptor -f json discover -T example.com | jq '.assets[] | select(.type == "subdomain") | .value'

# Count assets by type
domainraptor -f json discover -T example.com | jq '.assets | group_by(.type) | map({type: .[0].type, count: length})'

# Get critical issues
domainraptor -f json assess config example.com | jq '.config_issues[] | select(.severity == "HIGH" or .severity == "CRITICAL")'
```

---

### YAML

Best for: Human-readable output, configuration

```bash
domainraptor -f yaml discover -T example.com
domainraptor -f yaml -o results.yaml discover -T example.com
```

**Example:**

```yaml
scan_id: abc123
target: example.com
type: discover
status: completed
timestamp: '2025-01-15T10:30:00Z'
duration_seconds: 45.2
summary:
  assets: 24
  services: 5
  certificates: 8
  vulnerabilities: 0
  config_issues: 7
assets:
  - type: ip
    value: 93.184.216.34
    source: dns
    first_seen: '2025-01-15T10:30:05Z'
  - type: subdomain
    value: www.example.com
    source: crt_sh
    first_seen: '2025-01-15T10:30:10Z'
    metadata:
      ip: 93.184.216.34
```

---

### CSV

Best for: Spreadsheets, data analysis, Excel import

```bash
domainraptor -f csv -o assets.csv discover -T example.com
```

**Example:**

```csv
type,value,source,first_seen,parent
ip,93.184.216.34,dns,2025-01-15T10:30:05Z,example.com
subdomain,www.example.com,crt_sh,2025-01-15T10:30:10Z,example.com
subdomain,mail.example.com,hackertarget,2025-01-15T10:30:12Z,example.com
subdomain,api.example.com,shodan,2025-01-15T10:30:15Z,example.com
```

**Import to Excel/Google Sheets:**

1. Open Excel/Sheets
2. Go to Data → Import
3. Select the CSV file
4. Choose comma delimiter

---

### HTML

Best for: Reports, sharing with stakeholders, presentations

```bash
domainraptor report generate example.com -f html -o report.html
```

**Features:**

- Styled with CSS
- Interactive tables (sortable)
- Charts and graphs
- Print-friendly
- Responsive design

**Structure:**

```
┌─────────────────────────────────────────────────────┐
│               Security Assessment Report            │
│                   example.com                       │
├─────────────────────────────────────────────────────┤
│ [Executive Summary]                                 │
├─────────────────────────────────────────────────────┤
│ [Discovered Assets] - Interactive table             │
├─────────────────────────────────────────────────────┤
│ [Security Findings] - Severity charts               │
├─────────────────────────────────────────────────────┤
│ [Remediation Steps] - Prioritized list              │
└─────────────────────────────────────────────────────┘
```

---

### Markdown

Best for: Documentation, GitHub wikis, README files

```bash
domainraptor report generate example.com -f md -o report.md
```

**Example:**

```markdown
# Security Assessment Report: example.com

**Generated:** 2025-01-15 10:30:00

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Assets | 24 |
| Vulnerabilities | 0 |
| Config Issues | 7 |
| Risk Level | MEDIUM |

## Discovered Assets

| Type | Value | Source |
|------|-------|--------|
| IP | 93.184.216.34 | dns |
| Subdomain | www.example.com | crt_sh |
| Subdomain | mail.example.com | hackertarget |

## Security Findings

### Configuration Issues

1. **SSL-001** (HIGH): TLS 1.0 enabled
2. **DNS-001** (MEDIUM): DNSSEC not enabled
3. **HDR-001** (MEDIUM): Missing X-Frame-Options

## Recommendations

1. Disable TLS 1.0 and 1.1
2. Enable DNSSEC for the domain
3. Add security headers to web server
```

---

### PDF

Best for: Formal reports, archival, printing

**Requires:** wkhtmltopdf (`apt install wkhtmltopdf` or `brew install wkhtmltopdf`)

```bash
domainraptor report generate example.com -f pdf -o report.pdf
```

**Features:**

- Professional formatting
- Table of contents
- Page numbers
- Cover page
- Print-ready

---

## Combining Formats

Generate multiple formats at once:

```bash
# Generate both JSON and HTML reports
domainraptor report generate example.com -f json -o report.json
domainraptor report generate example.com -f html -o report.html
```

Script to generate all formats:

```bash
#!/bin/bash
TARGET="example.com"
DATE=$(date +%Y%m%d)

domainraptor report generate $TARGET -f json -o "${TARGET}_${DATE}.json"
domainraptor report generate $TARGET -f html -o "${TARGET}_${DATE}.html"
domainraptor report generate $TARGET -f md -o "${TARGET}_${DATE}.md"
domainraptor report generate $TARGET -f csv -o "${TARGET}_${DATE}.csv"
```

---

## Disabling Formatting

### No Color

```bash
domainraptor --no-color discover -T example.com
```

### No Banner

```bash
domainraptor --no-banner discover -T example.com
```

### Plain Output (CI/CD friendly)

```bash
domainraptor --no-color --no-banner -f json discover -T example.com
```

---

**← [API Keys](API-Keys)** | **Next: [Scan Modes](Scan-Modes) →**
