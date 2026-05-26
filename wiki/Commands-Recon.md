# 🎯 Recon Commands

The `recon` command runs a centralized **Attack Surface Management (ASM)** workflow that aggregates every discovery source into a single comprehensive scan.

---

## Overview

```bash
domainraptor recon [OPTIONS] COMMAND [ARGS]
```

**Purpose:** Combine all reconnaissance providers (crt.sh, HackerTarget, Shodan, ZoomEye, Censys) in one orchestrated pass with deduplication, IP resolution and service enrichment.

---

## Commands

### `recon fullscan`

Run a full multi-source reconnaissance against a target:

```bash
domainraptor recon fullscan example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--output` | `-o` | Save full JSON report to file | None |
| `--max-results` | `-m` | Max results per source | 50 |
| `--shodan/--no-shodan` | | Enable Shodan | `True` |
| `--zoomeye/--no-zoomeye` | | Enable ZoomEye | `True` |
| `--censys/--no-censys` | | Enable Censys | `True` |
| `--crtsh/--no-crtsh` | | Enable crt.sh | `True` |
| `--hackertarget/--no-hackertarget` | | Enable HackerTarget | `True` |
| `--resolve-ips/--no-resolve-ips` | | Resolve subdomain IPs | `True` |
| `--save/--no-save` | | Persist to database | `True` |

API keys missing for Shodan/ZoomEye/Censys silently skip that source — the scan continues with what is configured.

**Data sources:**

| Source | Free | Provides |
|--------|------|----------|
| crt.sh | ✓ | Subdomains via Certificate Transparency |
| HackerTarget | ✓ | Subdomain enumeration |
| Shodan | API key | Hosts, ports, services, banners, CVEs |
| ZoomEye | API key | Hosts and subdomains |
| Censys | PAT | IP/host/certificate lookups |

**Output includes:**

- Subdomains with resolved A/AAAA records
- Open ports + service banners + version info per IP
- CVE list with CVSS scores (when Shodan returns vulns)
- Organization, ASN, country and geolocation
- SSL certificate metadata
- Source attribution for every finding

**Examples:**

```bash
# Default: every configured source
domainraptor recon fullscan example.com

# Comprehensive JSON dump for further processing
domainraptor recon fullscan example.com -o fullscan.json --max-results 200

# Only Shodan + Censys
domainraptor recon fullscan example.com --no-zoomeye --no-crtsh --no-hackertarget

# Free-only ASM (no API keys needed)
domainraptor recon fullscan example.com --no-shodan --no-zoomeye --no-censys
```

**Example output (truncated):**

```
ℹ Starting FULL ASM reconnaissance for: example.com
ℹ Sources enabled: crt.sh, HackerTarget, Shodan, Censys

  Discovering subdomains... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
  Resolving IPs...          ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
  Enriching with Shodan...  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

Findings:
  • Subdomains discovered: 47
  • Unique IPs:            18
  • Open services:         62
  • CVEs detected:         9

✓ Saved scan ID 142. Use `domainraptor report generate example.com -f html` to render.
```

---

## When to use `recon` vs `discover`

| Use case | Command |
|----------|---------|
| Single targeted source (e.g. crt.sh only) | `discover subdomains` |
| Full attack surface in one command | `recon fullscan` |
| Lightweight DNS-only enumeration | `discover dns` |
| End-to-end pipeline (`subdomains → IPs → services → CVEs`) | `recon fullscan` |

---

## Recommended workflow

```bash
# 1. Build the attack surface
domainraptor recon fullscan example.com

# 2. Enrich any discovered CVEs with KEV/EPSS/Exploit-DB
domainraptor assess exploits example.com --save

# 3. Generate an HTML report
domainraptor report generate example.com -f html -o report.html
```

---

**← [Discover Commands](Commands-Discover)** | **Next: [Assess Commands](Commands-Assess) →**
