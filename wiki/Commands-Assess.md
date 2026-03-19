# 🛡️ Assess Commands

The `assess` command evaluates security configurations and identifies vulnerabilities.

---

## Overview

```bash
domainraptor assess [OPTIONS] COMMAND [ARGS]
```

**Purpose:** Assess vulnerabilities, check security configurations, and identify outdated software.

---

## Global Assess Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--target` | `-T` | Target domain or IP | Required |
| `--save/--no-save` | | Save to database | `True` |

---

## Commands

### `assess vulns`

Check for known vulnerabilities:

```bash
domainraptor assess vulns example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--min-severity` | `-s` | Minimum severity (low, medium, high, critical) | `low` |
| `--cve-check` | | Check CVE databases | `True` |
| `--exploit-check` | | Check for public exploits | `False` |

**Examples:**

```bash
# Basic vulnerability check
domainraptor assess vulns example.com

# Only high and critical vulnerabilities
domainraptor assess vulns example.com --min-severity high

# Include exploit availability check
domainraptor assess vulns example.com --exploit-check
```

**Example Output (No Vulnerabilities):**

```
ℹ Vulnerability assessment for: example.com
ℹ Min severity: low | CVE check: True

╭─────────────────── Scan Summary ───────────────────╮
│ Target: example.com                                │
│ Type: assess_vulns                                 │
│ Status: completed                                  │
│ Duration: 12.5s                                    │
│                                                    │
│ Findings:                                          │
│   • Vulnerabilities: 0                             │
╰────────────────────────────────────────────────────╯

✓ No vulnerabilities found!
```

**Example Output (Vulnerabilities Found):**

```
ℹ Vulnerability assessment for: vulnerable-site.com

                    Discovered Vulnerabilities
┏━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CVE ID          ┃ Severity ┃ CVSS    ┃ Description                        ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ CVE-2024-1234   │ CRITICAL │ 9.8     │ Remote code execution in Apache... │
│ CVE-2024-5678   │ HIGH     │ 7.5     │ SQL injection in login form...     │
│ CVE-2023-9012   │ MEDIUM   │ 5.3     │ Information disclosure via...      │
└─────────────────┴──────────┴─────────┴────────────────────────────────────┘

⚠ Found 3 vulnerabilities (1 critical, 1 high, 1 medium)
```

---

### `assess config`

Check security configurations:

```bash
domainraptor assess config example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--category` | `-c` | Category: all, ssl, dns, headers | `all` |
| `--strict` | | Use strict security standards | `False` |

**Examples:**

```bash
# Check all configurations
domainraptor assess config example.com

# SSL/TLS configuration only
domainraptor assess config example.com --category ssl

# DNS security only
domainraptor assess config example.com --category dns

# HTTP headers only
domainraptor assess config example.com --category headers

# Strict mode (more findings)
domainraptor assess config example.com --strict
```

**Example Output:**

```
ℹ Configuration assessment for: example.com
ℹ Category: all

╭─────────────────── Scan Summary ───────────────────╮
│ Target: example.com                                │
│ Type: assess_config                                │
│ Status: completed                                  │
│ Duration: 8.3s                                     │
│                                                    │
│ Findings:                                          │
│   • Config Issues: 7                               │
╰────────────────────────────────────────────────────╯

                       Configuration Issues
┏━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ ID      ┃ Severity ┃ Category ┃ Title                              ┃ Asset          ┃
┡━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ SSL-001 │ HIGH     │ ssl      │ TLS 1.0 enabled (deprecated)       │ example.com:443│
│ SSL-002 │ MEDIUM   │ ssl      │ Weak cipher suites enabled         │ example.com:443│
│ DNS-001 │ MEDIUM   │ dns      │ DNSSEC not enabled                 │ example.com    │
│ DNS-002 │ LOW      │ dns      │ DMARC policy set to none           │ example.com    │
│ DNS-003 │ LOW      │ dns      │ No DKIM records found              │ example.com    │
│ HDR-001 │ MEDIUM   │ headers  │ Missing X-Frame-Options header     │ example.com    │
│ HDR-002 │ MEDIUM   │ headers  │ Missing Content-Security-Policy    │ example.com    │
└─────────┴──────────┴──────────┴────────────────────────────────────┴────────────────┘

Issues by Category:
  ssl: 2
  dns: 3
  headers: 2
```

---

### Configuration Checks Reference

#### SSL/TLS Checks

| ID | Severity | Check |
|----|----------|-------|
| SSL-001 | HIGH | TLS 1.0/1.1 enabled |
| SSL-002 | MEDIUM | Weak cipher suites |
| SSL-003 | HIGH | Certificate expired |
| SSL-004 | HIGH | No modern TLS support |
| SSL-005 | MEDIUM | Certificate chain incomplete |
| SSL-006 | LOW | HSTS not enabled |
| SSL-007 | LOW | OCSP stapling not enabled |
| SSL-010 | HIGH | Self-signed certificate |
| SSL-020 | HIGH | Invalid certificate |

#### DNS Security Checks

| ID | Severity | Check |
|----|----------|-------|
| DNS-001 | MEDIUM | DNSSEC not enabled |
| DNS-010 | LOW | SPF record missing |
| DNS-011 | LOW | SPF too permissive |
| DNS-020 | LOW | DMARC missing |
| DNS-021 | LOW | DMARC policy none |
| DNS-030 | LOW | DKIM not found |
| DNS-040 | LOW | CAA records missing |
| DNS-050 | INFO | Multiple NS providers |
| DNS-051 | INFO | Single NS provider |

#### HTTP Header Checks

| ID | Severity | Check |
|----|----------|-------|
| HDR-001 | MEDIUM | X-Frame-Options missing |
| HDR-002 | MEDIUM | Content-Security-Policy missing |
| HDR-003 | LOW | X-Content-Type-Options missing |
| HDR-004 | LOW | X-XSS-Protection missing |
| HDR-005 | MEDIUM | Strict-Transport-Security missing |
| HDR-006 | LOW | Referrer-Policy missing |
| HDR-007 | LOW | Permissions-Policy missing |
| HDR-010 | INFO | Server header exposed |
| HDR-011 | INFO | X-Powered-By exposed |
| HDR-ERR | HIGH | Failed to fetch headers |

---

### `assess outdated`

Check for outdated software versions:

```bash
domainraptor assess outdated example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--include-minor` | | Include minor version updates | `False` |

**Examples:**

```bash
# Check for major outdated versions
domainraptor assess outdated example.com

# Include minor version updates
domainraptor assess outdated example.com --include-minor
```

**Example Output (No Issues):**

```
ℹ Outdated software check for: example.com

╭─────────────────── Scan Summary ───────────────────╮
│ Target: example.com                                │
│ Type: assess_outdated                              │
│ Status: completed                                  │
│ Duration: 5.2s                                     │
╰────────────────────────────────────────────────────╯

✓ All detected software is up to date!
```

**Example Output (Outdated Software):**

```
ℹ Outdated software check for: outdated-site.com

                    Outdated Software
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Software       ┃ Current Version ┃ Latest Version  ┃ Severity ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ nginx          │ 1.18.0          │ 1.25.4          │ HIGH     │
│ OpenSSL        │ 1.1.1           │ 3.2.1           │ CRITICAL │
│ PHP            │ 7.4.33          │ 8.3.4           │ HIGH     │
│ jQuery         │ 2.1.4           │ 3.7.1           │ MEDIUM   │
└────────────────┴─────────────────┴─────────────────┴──────────┘

⚠ Found 4 outdated components
```

---

## Full Assessment Example

Perform a complete security assessment:

```bash
# Step 1: Check vulnerabilities
domainraptor assess vulns example.com

# Step 2: Check configuration
domainraptor assess config example.com

# Step 3: Check outdated software
domainraptor assess outdated example.com
```

Or run all assessments and generate a report:

```bash
# Run discovery first
domainraptor discover -T example.com

# Run all assessments
domainraptor assess vulns example.com
domainraptor assess config example.com
domainraptor assess outdated example.com

# Generate comprehensive report
domainraptor report generate example.com -f html -o security_assessment.html --remediation
```

---

## Understanding Severity Levels

| Severity | Description | Action Required |
|----------|-------------|-----------------|
| **CRITICAL** | Immediate exploitation risk | Fix immediately |
| **HIGH** | Significant security risk | Fix within 24-48 hours |
| **MEDIUM** | Moderate security concern | Fix within 1-2 weeks |
| **LOW** | Minor security improvement | Fix when convenient |
| **INFO** | Informational finding | Review and assess |

---

## Remediation Tips

Each finding includes remediation guidance. Generate a report with remediation steps:

```bash
domainraptor report generate example.com --remediation -f html -o report.html
```

Common remediations:

| Issue | Remediation |
|-------|-------------|
| TLS 1.0/1.1 enabled | Configure server to use TLS 1.2+ only |
| DNSSEC not enabled | Enable DNSSEC at your DNS provider |
| DMARC missing | Add DMARC TXT record to DNS |
| Missing security headers | Configure web server to add headers |
| Outdated software | Update to latest stable versions |

---

**← [Discover Commands](Commands-Discover)** | **Next: [Report Commands](Commands-Report) →**
