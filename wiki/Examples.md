# 📚 Examples & Use Cases

Real-world examples and workflows for DomainRaptor.

---

## Quick Reference

```bash
# Basic discovery
domainraptor discover -T example.com

# Security assessment
domainraptor assess config example.com

# Generate report
domainraptor report generate example.com -f html -o report.html

# Monitor changes
domainraptor watch add example.com --interval 24h
```

---

## Use Case 1: Initial Reconnaissance

**Scenario:** You need to quickly assess the attack surface of a new target.

### Step 1: Quick Discovery

```bash
# Start with quick mode for initial overview
domainraptor -m quick discover -T example.com
```

### Step 2: Full Discovery

```bash
# If promising, run full discovery
domainraptor discover -T example.com --subdomains --dns --certs --whois
```

### Step 3: Port Scanning (if authorized)

```bash
# Add port scanning
domainraptor discover -T example.com --ports
```

### Step 4: Review Results

```bash
# Check what was found
domainraptor db show 1

# Export for analysis
domainraptor db export 1 -o recon_results.json
```

---

## Use Case 2: Security Audit

**Scenario:** Complete security assessment for compliance or audit purposes.

### Full Audit Workflow

```bash
#!/bin/bash
# security_audit.sh - Complete security audit workflow

TARGET="example.com"
DATE=$(date +%Y%m%d)
OUTPUT_DIR="./audit_${TARGET}_${DATE}"

mkdir -p "$OUTPUT_DIR"

echo "=== Starting Security Audit for $TARGET ==="

# Phase 1: Discovery
echo "[1/5] Running discovery..."
domainraptor -m deep discover -T "$TARGET" \
  --subdomains \
  --dns \
  --certs \
  --ports \
  --whois

# Phase 2: Vulnerability Assessment
echo "[2/5] Checking vulnerabilities..."
domainraptor assess vulns "$TARGET"

# Phase 3: Configuration Assessment
echo "[3/5] Assessing configuration..."
domainraptor assess config "$TARGET"

# Phase 4: Outdated Software Check
echo "[4/5] Checking for outdated software..."
domainraptor assess outdated "$TARGET"

# Phase 5: Generate Reports
echo "[5/5] Generating reports..."
domainraptor report generate "$TARGET" -f html -o "$OUTPUT_DIR/report.html" --remediation
domainraptor report generate "$TARGET" -f json -o "$OUTPUT_DIR/report.json"
domainraptor report summary "$TARGET" -f md -o "$OUTPUT_DIR/summary.md"

echo "=== Audit Complete ==="
echo "Reports saved to: $OUTPUT_DIR"
```

### Review Findings

```bash
# View summary
domainraptor report summary example.com

# Export detailed findings
domainraptor -f json assess config example.com | jq '.config_issues[] | select(.severity == "HIGH")'
```

---

## Use Case 3: Continuous Monitoring

**Scenario:** Monitor your organization's domains for changes and new threats.

### Setup Monitoring

```bash
# Add production domains to watch list
domainraptor watch add example.com --interval 24h --tags "production,critical"
domainraptor watch add api.example.com --interval 6h --tags "production,api"
domainraptor watch add staging.example.com --interval 24h --tags "staging"

# Add certificate monitoring
domainraptor watch add example.com --type certificate --interval 7d
```

### Configure Notifications

```bash
# Add Slack notifications
domainraptor watch add example.com \
  --notify webhook:https://hooks.slack.com/services/xxx/yyy/zzz

# Add email notifications
domainraptor watch add example.com \
  --notify email:security@example.com
```

### Automate with Cron

```bash
# Add to crontab
# Run checks every 6 hours
0 */6 * * * domainraptor watch run >> /var/log/domainraptor-watch.log 2>&1

# Weekly summary report
0 9 * * 1 domainraptor report summary example.com | mail -s "Weekly Security Summary" security@example.com
```

### Check Status

```bash
# View all watched targets
domainraptor watch list

# Check specific target status
domainraptor watch status example.com

# View recent changes
domainraptor compare history example.com --scans 7
```

---

## Use Case 4: Bug Bounty Reconnaissance

**Scenario:** Perform reconnaissance for bug bounty programs while respecting scope.

### Passive Reconnaissance (Stealth Mode)

```bash
# Start with passive recon only
domainraptor -m stealth discover -T target.com

# Extract subdomains for scope verification
domainraptor -f json discover subdomains target.com | \
  jq -r '.assets[] | .value' > subdomains.txt
```

### In-Scope Target Analysis

```bash
# After confirming scope, perform deeper analysis
domainraptor -m standard discover -T inscope.target.com --ports

# Check security configurations
domainraptor assess config inscope.target.com

# Export findings
domainraptor report generate inscope.target.com -f md -o findings.md
```

### Finding Documentation

```bash
# Document specific finding
cat << EOF > finding_SSL001.md
## Finding: TLS 1.0 Enabled

**Target:** inscope.target.com
**Severity:** High
**Category:** SSL/TLS Configuration

### Description
The server supports TLS 1.0, which is deprecated and has known vulnerabilities.

### Evidence
\`\`\`
$(domainraptor -f json assess config inscope.target.com | jq '.config_issues[] | select(.id == "SSL-001")')
\`\`\`

### Remediation
Disable TLS 1.0 and 1.1 in server configuration.
EOF
```

---

## Use Case 5: CI/CD Security Pipeline

**Scenario:** Integrate DomainRaptor into CI/CD for automated security checks.

### GitHub Actions Workflow

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM
  workflow_dispatch:

env:
  TARGET: example.com

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - name: Install DomainRaptor
        run: pip install domainraptor

      - name: Configure API Keys
        run: |
          domainraptor config set SHODAN_API_KEY ${{ secrets.SHODAN_API_KEY }}

      - name: Run Discovery
        run: domainraptor discover -T ${{ env.TARGET }}

      - name: Run Security Assessment
        run: domainraptor assess config ${{ env.TARGET }}

      - name: Check for Critical Issues
        run: |
          CRITICAL=$(domainraptor -f json assess vulns ${{ env.TARGET }} | \
            jq '[.vulnerabilities[] | select(.severity == "CRITICAL")] | length')
          if [ "$CRITICAL" -gt 0 ]; then
            echo "Critical vulnerabilities found!"
            exit 1
          fi

      - name: Generate Report
        run: |
          domainraptor report generate ${{ env.TARGET }} -f html -o report.html

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: report.html

      - name: Notify on Failure
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "Security scan failed for ${{ env.TARGET }}"
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any

    environment {
        TARGET = 'example.com'
        SHODAN_API_KEY = credentials('shodan-api-key')
    }

    stages {
        stage('Setup') {
            steps {
                sh 'pip install domainraptor'
                sh 'domainraptor config set SHODAN_API_KEY $SHODAN_API_KEY'
            }
        }

        stage('Discovery') {
            steps {
                sh 'domainraptor discover -T $TARGET'
            }
        }

        stage('Assessment') {
            steps {
                sh 'domainraptor assess config $TARGET'
                sh 'domainraptor assess vulns $TARGET'
            }
        }

        stage('Report') {
            steps {
                sh 'domainraptor report generate $TARGET -f html -o report.html'
                archiveArtifacts artifacts: 'report.html'
            }
        }
    }

    post {
        failure {
            slackSend channel: '#security-alerts',
                      message: "Security scan failed for ${TARGET}"
        }
    }
}
```

---

## Use Case 6: Incident Response

**Scenario:** Quickly assess potential compromise indicators.

### Immediate Assessment

```bash
# Quick check after suspicious activity
domainraptor -m quick discover -T compromised.example.com

# Check for unauthorized changes
domainraptor compare baseline compromised.example.com
```

### Detailed Investigation

```bash
# Full discovery with all sources
domainraptor -m deep discover -T compromised.example.com

# Check WHOIS for recent changes
domainraptor discover whois compromised.example.com

# Export all data for forensics
domainraptor db export $(domainraptor db list --target compromised.example.com -f json | jq -r '.[0].scan_id') \
  -o forensic_data.json
```

### Timeline Analysis

```bash
# Compare with historical data
domainraptor compare history compromised.example.com --scans 10

# Generate incident report
domainraptor report generate compromised.example.com \
  -f html \
  -o incident_report.html \
  --history \
  --remediation
```

---

## Use Case 7: Multi-Domain Assessment

**Scenario:** Assess security across multiple domains in your organization.

### Batch Processing Script

```bash
#!/bin/bash
# multi_domain_scan.sh

DOMAINS=(
    "example.com"
    "api.example.com"
    "shop.example.com"
    "blog.example.com"
)

OUTPUT_DIR="./multi_scan_$(date +%Y%m%d)"
mkdir -p "$OUTPUT_DIR"

for domain in "${DOMAINS[@]}"; do
    echo "Scanning: $domain"

    # Discovery
    domainraptor discover -T "$domain"

    # Assessment
    domainraptor assess config "$domain"

    # Individual report
    domainraptor report generate "$domain" -f json -o "$OUTPUT_DIR/${domain}.json"
done

# Generate summary
echo "=== Multi-Domain Security Summary ===" > "$OUTPUT_DIR/summary.txt"
for domain in "${DOMAINS[@]}"; do
    echo "--- $domain ---" >> "$OUTPUT_DIR/summary.txt"
    domainraptor report summary "$domain" >> "$OUTPUT_DIR/summary.txt"
    echo "" >> "$OUTPUT_DIR/summary.txt"
done

echo "Scan complete. Results in $OUTPUT_DIR"
```

### Aggregate Analysis

```bash
# Combine all JSON reports
jq -s '.' ./multi_scan_*/*.json > combined_report.json

# Find domains with critical issues
jq '.[] | select(.config_issues[] | .severity == "CRITICAL") | .target' combined_report.json

# Count issues by severity across all domains
jq '[.[].config_issues[].severity] | group_by(.) | map({severity: .[0], count: length})' combined_report.json
```

---

## Command Quick Reference

### Discovery

```bash
domainraptor discover -T example.com                    # Full discovery
domainraptor discover subdomains example.com            # Subdomains only
domainraptor discover dns example.com                   # DNS records only
domainraptor discover certs example.com                 # Certificates only
domainraptor discover ports example.com                 # Ports only
domainraptor discover whois example.com                 # WHOIS only
```

### Assessment

```bash
domainraptor assess vulns example.com                   # Vulnerabilities
domainraptor assess config example.com                  # Configuration
domainraptor assess outdated example.com                # Outdated software
```

### Reporting

```bash
domainraptor report generate example.com -f html        # HTML report
domainraptor report summary example.com                 # Executive summary
domainraptor report list                                # List all reports
domainraptor report export example.com                  # Export raw data
```

### Monitoring

```bash
domainraptor watch add example.com                      # Add to watchlist
domainraptor watch list                                 # List watched targets
domainraptor watch run                                  # Run checks
domainraptor watch status example.com                   # Check status
```

### Database

```bash
domainraptor db list                                    # List all scans
domainraptor db show 1                                  # Show scan details
domainraptor db export 1 -o scan.json                   # Export scan
domainraptor db stats                                   # Database stats
domainraptor db prune --days 30                         # Clean old scans
```

### Comparison

```bash
domainraptor compare history example.com                # Compare history
domainraptor compare baseline example.com               # Compare to baseline
domainraptor compare targets example.com test.com       # Compare targets
```

---

**← [Scan Modes](Scan-Modes)** | **[Home](Home)**
