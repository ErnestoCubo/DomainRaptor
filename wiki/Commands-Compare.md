# 📊 Compare Commands

The `compare` command analyzes differences between scans, targets, and baselines.

---

## Overview

```bash
domainraptor compare [OPTIONS] COMMAND [ARGS]
```

**Purpose:** Compare scan results to identify changes, track evolution, and detect anomalies.

---

## Commands

### `compare history`

Compare scan history for a target:

```bash
domainraptor compare history example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--scans` | `-s` | Number of scans to compare | 2 |
| `--output` | `-o` | Output file path | stdout |
| `--format` | `-f` | Output format: table, json | `table` |

**Examples:**

```bash
# Compare last 2 scans (default)
domainraptor compare history example.com

# Compare last 5 scans
domainraptor compare history example.com --scans 5

# Export as JSON
domainraptor compare history example.com -f json -o history.json
```

**Example Output:**

```
ℹ Comparing scan history for: example.com
ℹ Last 2 scans

  Comparing results... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

ℹ Found 4 change(s) between scans:

                            Detected Changes
┏━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Type     ┃ Asset Type  ┃ Value                 ┃ Details                        ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ NEW      │ subdomain   │ api-v2.example.com    │ New subdomain discovered       │
│ NEW      │ port        │ 8443                  │ New port opened                │
│ MODIFIED │ certificate │ *.example.com         │ expires: 2024-12-01 → 2025-... │
│ REMOVED  │ subdomain   │ old-api.example.com   │ Subdomain no longer resolves   │
└──────────┴─────────────┴───────────────────────┴────────────────────────────────┘

Summary:
  NEW: 2 | MODIFIED: 1 | REMOVED: 1
```

---

### `compare scans`

Compare two specific scan results:

```bash
domainraptor compare scans <SCAN_ID_1> <SCAN_ID_2>
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--detail` | `-d` | Show detailed differences | `False` |
| `--output` | `-o` | Output file path | stdout |
| `--format` | `-f` | Output format: table, json | `table` |

**Examples:**

```bash
# Compare two scans by ID
domainraptor compare scans abc123 def456

# With detailed output
domainraptor compare scans abc123 def456 --detail

# Export to JSON
domainraptor compare scans abc123 def456 -f json -o diff.json
```

**Example Output:**

```
ℹ Comparing scans: abc123 vs def456

Scan 1: abc123 (2025-01-10 10:00)
Scan 2: def456 (2025-01-15 10:00)

                         Comparison Results
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Category          ┃ Scan abc123 ┃ Scan def456 ┃ Change             ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ Subdomains        │ 10          │ 12          │ +2                 │
│ IP Addresses      │ 3           │ 3           │ No change          │
│ Open Ports        │ 4           │ 5           │ +1                 │
│ Certificates      │ 3           │ 3           │ 1 renewed          │
│ Config Issues     │ 5           │ 3           │ -2 (fixed)         │
│ Vulnerabilities   │ 0           │ 0           │ No change          │
└───────────────────┴─────────────┴─────────────┴────────────────────┘

New Assets:
  + subdomain: api-v2.example.com
  + subdomain: staging.example.com
  + port: 8443/tcp

Fixed Issues:
  - SSL-001: TLS 1.0 enabled (fixed)
  - HDR-001: Missing X-Frame-Options (fixed)
```

---

### `compare targets`

Compare two different targets side by side:

```bash
domainraptor compare targets <TARGET_1> <TARGET_2>
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--categories` | `-c` | Categories to compare | All |
| `--output` | `-o` | Output file path | stdout |
| `--format` | `-f` | Output format: table, json | `table` |

**Examples:**

```bash
# Compare two targets
domainraptor compare targets example.com example.org

# Compare specific categories
domainraptor compare targets example.com example.org --categories ssl,headers

# Export comparison
domainraptor compare targets example.com example.org -f json -o compare.json
```

**Example Output:**

```
ℹ Comparing targets: example.com vs example.org

                         Target Comparison
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┓
┃ Attribute           ┃ example.com       ┃ example.org       ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━┩
│ Subdomains          │ 12                │ 8                 │
│ IP Addresses        │ 3                 │ 2                 │
│ Open Ports          │ 5                 │ 3                 │
│ SSL Grade           │ A                 │ B                 │
│ TLS Version         │ 1.3               │ 1.2               │
│ DNSSEC              │ ✓ Enabled         │ ✗ Disabled        │
│ DMARC               │ ✓ Enforced        │ ✗ None            │
│ Security Headers    │ 5/7               │ 3/7               │
│ Config Issues       │ 2                 │ 6                 │
│ Vulnerabilities     │ 0                 │ 1                 │
└─────────────────────┴───────────────────┴───────────────────┘

Security Score:
  example.com: 85/100 (Good)
  example.org: 62/100 (Needs Improvement)
```

---

### `compare baseline`

Compare current state against a baseline scan:

```bash
domainraptor compare baseline example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--baseline` | `-b` | Baseline scan ID | Auto |
| `--set-baseline` | `-s` | Set current scan as baseline | `False` |
| `--output` | `-o` | Output file path | stdout |
| `--format` | `-f` | Output format: table, json | `table` |

**Examples:**

```bash
# Compare against baseline
domainraptor compare baseline example.com

# Use specific baseline
domainraptor compare baseline example.com --baseline abc123

# Set current as new baseline
domainraptor compare baseline example.com --set-baseline
```

**Example Output:**

```
ℹ Comparing against baseline for: example.com
ℹ Baseline: abc123 (2025-01-01 00:00)
ℹ Current: def456 (2025-01-15 10:00)

                      Baseline Comparison
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Metric            ┃ Baseline   ┃ Current    ┃ Drift              ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ Attack Surface    │ 15 assets  │ 18 assets  │ +20% ⚠             │
│ Open Ports        │ 4 ports    │ 5 ports    │ +25% ⚠             │
│ Security Issues   │ 3 issues   │ 2 issues   │ -33% ✓             │
│ SSL Grade         │ A          │ A          │ No change ✓        │
│ Header Score      │ 5/7        │ 6/7        │ Improved ✓         │
└───────────────────┴────────────┴────────────┴────────────────────┘

Drift Summary:
  ⚠ Attack surface has grown by 20%
  ⚠ New port opened: 8443
  ✓ Fixed 1 security issue
  ✓ Added X-Content-Type-Options header

Recommendation: Review new assets for security compliance
```

---

## Change Types

| Type | Icon | Description |
|------|------|-------------|
| `NEW` | + | New asset or finding discovered |
| `REMOVED` | - | Asset or finding no longer present |
| `MODIFIED` | ~ | Asset or finding changed |
| `IMPROVED` | ✓ | Security improvement |
| `DEGRADED` | ⚠ | Security degradation |

---

## Use Cases

### 1. Post-Deployment Verification

```bash
# Before deployment - create baseline
domainraptor discover -T example.com
domainraptor compare baseline example.com --set-baseline

# After deployment - compare
domainraptor discover -T example.com
domainraptor compare baseline example.com
```

### 2. Incident Investigation

```bash
# Compare before and after suspected incident
domainraptor compare scans scan_before_incident scan_after_incident --detail
```

### 3. Multi-Environment Comparison

```bash
# Compare production vs staging
domainraptor compare targets prod.example.com staging.example.com
```

### 4. Security Trend Analysis

```bash
# Compare multiple historical scans
domainraptor compare history example.com --scans 10
```

---

## Automation Examples

### CI/CD Integration

```bash
#!/bin/bash
# Compare against baseline in CI/CD

domainraptor discover -T example.com
RESULT=$(domainraptor compare baseline example.com -f json)

# Check for degradation
if echo "$RESULT" | jq -e '.degraded | length > 0' > /dev/null; then
    echo "Security degradation detected!"
    exit 1
fi
```

### Weekly Comparison Report

```bash
#!/bin/bash
# Generate weekly comparison report

domainraptor compare history example.com --scans 7 \
  -f json -o weekly_changes.json

# Send to monitoring system
curl -X POST https://monitoring.example.com/api/report \
  -H "Content-Type: application/json" \
  -d @weekly_changes.json
```

---

**← [Watch Commands](Commands-Watch)** | **Next: [Database Commands](Commands-Database) →**
