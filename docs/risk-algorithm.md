# Risk Level Algorithm

DomainRaptor calculates a **Risk Score (0-100)** and **Risk Level** for each scan based on multiple weighted security factors.

## Overview

The risk assessment evaluates four categories of security posture:

| Category | Weight | Description |
|----------|--------|-------------|
| **Vulnerabilities** | 40% | CVE severity, CVSS scores, known exploits |
| **Configuration** | 25% | Security headers, SSL/TLS, misconfigurations |
| **Exposure** | 25% | Attack surface, sensitive ports, dev environments |
| **Reputation** | 10% | Blacklists, malicious indicators |

## Risk Levels

| Score | Level | Emoji | Action Required |
|-------|-------|-------|-----------------|
| 80-100 | CRITICAL | 🔴 | Immediate action required |
| 60-79 | HIGH | 🟠 | Action within 7 days |
| 40-59 | MEDIUM | 🟡 | Plan mitigation activities |
| 20-39 | LOW | 🔵 | Improvements recommended |
| 0-19 | INFO | ⚪ | Good security posture |

## Formula

```
Risk Score = Vuln_Score × 0.40 + Config_Score × 0.25 + Exposure_Score × 0.25 + Reputation_Score × 0.10
```

Each category calculates raw points which are then weighted. The maximum contribution per category is capped to prevent any single category from dominating.

---

## Category Details

### 1. Vulnerability Score (40%)

Evaluates discovered CVEs and security vulnerabilities.

| Factor | Points |
|--------|--------|
| CRITICAL vulnerability | +25 |
| HIGH vulnerability | +15 |
| MEDIUM vulnerability | +5 |
| LOW vulnerability | +1 |
| CVSS score ≥ 9.0 (bonus) | +10 |
| Known exploit available | +15 (max 30 total) |

**Examples:**

- 2 CRITICAL vulns = 50 raw points → 20 weighted (capped at 40)
- 1 HIGH + 2 MEDIUM = 25 raw points → 10 weighted

### 2. Configuration Score (25%)

Evaluates security headers, SSL/TLS configuration, and best practices.

| Factor | Points |
|--------|--------|
| CRITICAL config issue | +20 |
| HIGH config issue | +12 |
| MEDIUM config issue | +6 |
| LOW config issue | +2 |
| Missing HSTS header | +8 |
| Missing CSP header | +6 |
| DNSSEC not enabled | +5 |
| SSL certificate expired | +15 |
| SSL expires < 30 days | +8 |
| SSL expires < 90 days | +3 |

**Security Headers Checked:**

- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy

### 3. Exposure Score (25%)

Evaluates attack surface and infrastructure exposure.

| Factor | Points |
|--------|--------|
| > 50 subdomains | +10 |
| > 20 subdomains | +5 |
| dev/staging/test exposed | +8 each (max 24) |
| SSH port (22) exposed | +5 |
| RDP port (3389) exposed | +8 |
| Database ports exposed | +10 each |
| Admin ports exposed | +3 each |
| > 10 unique IPs | +5 |

**Sensitive Ports:**

- SSH: 22
- RDP: 3389
- Databases: 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB), 6379 (Redis), 1433 (MSSQL), 5984 (CouchDB)
- Admin: 8080, 8443, 9000, 9090, 10000

**Dev/Staging Patterns Detected:**

- dev., dev-
- staging., staging-
- test., test-
- uat., qa., demo.
- sandbox., local.
- internal., admin.
- backend.

### 4. Reputation Score (10%)

Evaluates external reputation data from threat intelligence sources.

| Factor | Points |
|--------|--------|
| VirusTotal malicious > 0 | +30 |
| VirusTotal suspicious > 0 | +10 |
| On security blacklist | +20 |

---

## Example Output

### JSON Format

```json
{
  "risk_assessment": {
    "score": 67.3,
    "level": "HIGH",
    "level_description": "Significant risks - remediation recommended within 7 days",
    "breakdown": {
      "vulnerabilities": 28.0,
      "configuration": 18.5,
      "exposure": 15.8,
      "reputation": 5.0
    },
    "top_factors": [
      "2 CRITICAL vulnerabilities found",
      "SSH port (22) exposed to internet",
      "dev.example.com staging environment exposed",
      "SSL certificate expires in 15 days",
      "Missing Content-Security-Policy header"
    ]
  }
}
```

### CLI Display

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃              Risk Assessment                     ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Level: 🟠 HIGH                                   ┃
┃ Score: 67.3 / 100                                ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Vulnerabilities: 28.0                            ┃
┃ Configuration:   18.5                            ┃
┃ Exposure:        15.8                            ┃
┃ Reputation:       5.0                            ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

---

## Weight Justification

The weights (40/25/25/10) were chosen based on:

### Vulnerabilities (40%)

- **Highest weight** because known CVEs represent direct exploitable risks
- A single critical vulnerability can lead to full compromise
- This aligns with industry standards (CVSS prioritizes vulnerabilities)

### Configuration (25%)

- Misconfigurations are the #2 cause of breaches (OWASP)
- Easy to fix but often overlooked
- Security headers prevent entire classes of attacks

### Exposure (25%)

- Large attack surface = more opportunities for attackers
- Exposed dev/staging environments often have weaker security
- Internal services exposed to internet are high-risk

### Reputation (10%)

- **Lowest weight** because it's reactive (already compromised or associated with malware)
- Can have false positives
- Important signal but shouldn't dominate the score

---

## Customizing Weights

Future versions will support custom weights via configuration:

```yaml
# ~/.config/domainraptor/config.yaml
risk:
  weights:
    vulnerability: 0.40
    configuration: 0.25
    exposure: 0.25
    reputation: 0.10
  thresholds:
    critical: 80
    high: 60
    medium: 40
    low: 20
```

---

## Usage

### In CLI

```bash
# Generate report with risk assessment
domainraptor report generate -T example.com --format html

# Full recon includes risk in output
domainraptor recon -T example.com --json
```

### In Code

```python
from domainraptor.core.risk import calculate_risk_level, RiskLevel

# Calculate risk for a scan
risk = calculate_risk_level(scan_result)

print(f"Score: {risk.score}")
print(f"Level: {risk.level.value}")
print(f"Top factors: {risk.top_factors}")

# Check specific level
if risk.level in (RiskLevel.CRITICAL, RiskLevel.HIGH):
    send_alert("Urgent security review needed!")
```

---

## FAQ

### Q: Why is my score high with no vulnerabilities?

Configuration and exposure issues can still contribute 50% of the score. Check:

- Missing security headers (HSTS, CSP)
- Exposed dev/staging environments
- Sensitive ports open (SSH, RDP, databases)
- Large number of subdomains

### Q: Can the score exceed 100?

No. Each category is capped at its maximum contribution:

- Vulnerabilities: max 40 points
- Configuration: max 25 points
- Exposure: max 25 points
- Reputation: max 10 points

### Q: How often should I re-scan?

- **High/Critical**: Weekly or after any changes
- **Medium**: Monthly
- **Low/Info**: Quarterly

### Q: Which factors contribute most?

The `top_factors` field in the output shows the top 5 contributing factors, sorted by points. Focus remediation on these first.

---

## Related Commands

- `domainraptor assess vulns` - Scan for vulnerabilities only
- `domainraptor assess headers` - Check security headers
- `domainraptor discover subdomains` - Enumerate attack surface
- `domainraptor report generate` - Generate report with risk assessment
