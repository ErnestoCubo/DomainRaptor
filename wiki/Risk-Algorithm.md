# 📊 Risk Level Algorithm

DomainRaptor calculates a **Risk Score (0-100)** and **Risk Level** for every scan based on multiple weighted security factors. The score appears in every report (HTML, Markdown, JSON, YAML) and drives the **Risk Assessment** section.

---

## Overview

The risk assessment evaluates four categories of security posture:

| Category | Weight | Description |
|----------|--------|-------------|
| **Vulnerabilities** | 40% | CVE severity, CVSS scores, KEV/EPSS, known exploits |
| **Configuration** | 25% | Security headers, SSL/TLS, misconfigurations |
| **Exposure** | 25% | Attack surface, sensitive ports, dev environments |
| **Reputation** | 10% | Blacklists, malicious indicators |

---

## Risk Levels

| Score | Level | Emoji | Action Required |
|-------|-------|-------|-----------------|
| 80-100 | CRITICAL | 🔴 | Immediate action required |
| 60-79 | HIGH | 🟠 | Action within 7 days |
| 40-59 | MEDIUM | 🟡 | Plan mitigation activities |
| 20-39 | LOW | 🔵 | Improvements recommended |
| 0-19 | INFO | ⚪ | Good security posture |

---

## Formula

```
Risk Score = Vuln × 0.40 + Config × 0.25 + Exposure × 0.25 + Reputation × 0.10
```

Each category accumulates raw points, then the weighted contribution is capped (100 raw → full weight). This prevents a single category from monopolizing the score.

---

## 1. Vulnerability Score (40%)

| Factor | Points |
|--------|--------|
| CRITICAL vulnerability | +25 |
| HIGH vulnerability | +15 |
| MEDIUM vulnerability | +5 |
| LOW vulnerability | +1 |
| CVSS score ≥ 9.0 (bonus) | +10 |
| Public exploit available | +15 (max 30 total) |
| **CISA KEV listed** (actively exploited) | **+30** |
| **EPSS ≥ 0.5** (≥50% exploitation probability) | **+10** |

> KEV / EPSS / Exploit-DB bonuses are populated after running [`assess exploits`](Commands-Assess#assess-exploits) (which enriches stored CVEs from CISA KEV, the FIRST EPSS API and Exploit-DB).

**Examples:**

- 2 CRITICAL CVEs in KEV with high EPSS = `25×2 + 30×2 + 10×2 = 130` raw → capped → 40 weighted
- 1 HIGH CVE with public exploit but not in KEV = `15 + 15 = 30` raw → 12 weighted

---

## 2. Configuration Score (25%)

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

**Headers checked:** HSTS, CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy.

---

## 3. Exposure Score (25%)

| Factor | Points |
|--------|--------|
| > 50 subdomains | +10 |
| > 20 subdomains | +5 |
| dev/staging/test subdomain exposed | +8 each (max 24) |
| SSH (22) exposed | +5 |
| RDP (3389) exposed | +8 |
| Database port exposed (3306/5432/27017/6379/1433/5984) | +10 each |
| Admin port exposed (8080/8443/9000/9090/10000) | +3 each |
| > 10 unique IPs | +5 |

**Dev/staging patterns:** `dev.`, `dev-`, `staging.`, `test.`, `uat.`, `qa.`, `demo.`, `sandbox.`, `local.`, `internal.`, `admin.`, `backend.`, `api-dev.`, `api-test.`

---

## 4. Reputation Score (10%)

| Factor | Points |
|--------|--------|
| VirusTotal malicious > 0 | +30 |
| VirusTotal suspicious > 0 | +10 |
| On a security blacklist | +20 |

---

## Example Output

### JSON

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
      "CISA KEV (actively exploited): CVE-2021-44228",
      "2 CRITICAL vulnerabilities found",
      "SSH port (22) exposed to internet",
      "SSL certificate expires in 15 days",
      "Missing Content-Security-Policy header"
    ]
  }
}
```

### Markdown report (excerpt)

```
## Risk Assessment

| Metric         | Value                                    |
|----------------|------------------------------------------|
| **Risk Level** | 🟠 **HIGH**                              |
| **Risk Score** | 67.3/100                                 |
| Description    | Significant risks - remediate in 7 days  |
```

### CLI display

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

## Weight Rationale

- **Vulnerabilities (40%)** — Direct exploitable risk; CVSS already prioritises this category. KEV/EPSS make it even more actionable.
- **Configuration (25%)** — OWASP-reported #2 cause of breaches; cheap to fix.
- **Exposure (25%)** — Attack-surface size correlates strongly with compromise probability.
- **Reputation (10%)** — Reactive signal with noise potential; intentionally low.

---

## Customising Weights

Planned for a future release via `~/.config/domainraptor/config.yaml`:

```yaml
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

Today the weights and thresholds are constants in `src/domainraptor/core/risk.py`.

---

**See also:** [Assess Commands](Commands-Assess) · [Report Commands](Commands-Report) · [Exploit Enrichment](Commands-Assess#assess-exploits)
