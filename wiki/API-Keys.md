# 🔑 API Keys Setup

Configure API keys to unlock the full potential of DomainRaptor.

---

## Overview

DomainRaptor integrates with multiple security services. While basic functionality works without API keys (using crt.sh and HackerTarget), configuring them enables:

- More data sources
- Host/service enrichment
- CVE correlation
- Better accuracy

---

## Supported Services

| Service | Required | Free Tier | Features |
|---------|----------|-----------|----------|
| **Shodan** | Optional | ✓ 100/month | Port scanning, service detection, CVE lookup |
| **ZoomEye** | Optional | ✓ Subdomain free | Subdomain enumeration (host search paid) |
| **Censys (PAT)** | Optional | ✓ IP lookup free | Direct IP lookup (search paid) |
| **VirusTotal** | Optional | ✓ 500/day | Malware analysis, URL reputation |
| **NVD** | Optional | ✓ | CVE enrichment with descriptions, CVSS scores |

---

## Getting API Keys

### Shodan

1. Go to [https://account.shodan.io/](https://account.shodan.io/)
2. Create a free account
3. Navigate to **Account** → **API Key**
4. Copy your API key

**Free tier includes:**

- 100 query credits/month
- Basic search functionality
- Host lookups

```bash
domainraptor config set SHODAN_API_KEY AbCdEf123456789GhIjKlMnOpQrStUvWx
```

### ZoomEye

1. Go to [https://www.zoomeye.ai/](https://www.zoomeye.ai/)
2. Create a free account
3. Navigate to **Profile** → **API Key**
4. Copy your API key

**Free tier includes:**

- Subdomain discovery (unlimited)
- 3000 credits/month for general searches
- Host search requires paid credits

```bash
domainraptor config set ZOOMEYE_API_KEY 366C744C-52F4-6AA41-f5CF-1cf8603ff45
```

> ⚠️ **Note:** ZoomEye uses `api.zoomeye.ai` (international endpoint). The `.org` endpoint returns 403 for international users.

### Censys (Personal Access Token)

DomainRaptor uses the **Censys Platform API v3** with Personal Access Tokens (PAT).

1. Go to [https://platform.censys.io/settings/api](https://platform.censys.io/settings/api)
2. Create a free account
3. Generate a **Personal Access Token**
4. Copy the token (format: `censys_<prefix>_<secret>`)

**Free tier includes:**

- Direct IP lookup (`censys-host <ip>`) - **FREE**
- Host/certificate search - **Requires subscription**

```bash
domainraptor config set CENSYS_API_TOKEN censys_ffgeRyx8_BrN5ne8WzXvTKCpCMSVDAiyY
```

> 💡 **Tip:** Use `domainraptor discover censys-host 8.8.8.8` for free IP lookups.

### VirusTotal

1. Go to [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
2. Create a free account
3. Navigate to your profile → **API Key**
4. Copy your API key

**Free tier includes:**

- 500 requests/day
- 4 requests/minute
- Public reports only

```bash
domainraptor config set VIRUSTOTAL_API_KEY a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
```

### NVD (National Vulnerability Database)

1. Go to [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
2. Request a free API key
3. Receive key via email

**Without API key:**

- ~5 requests per 30 seconds
- Basic CVE lookup

**With API key:**

- ~50 requests per 30 seconds (10x faster)
- Same features, higher throughput

```bash
domainraptor config set NVD_API_KEY your_nvd_api_key_here
```

> 💡 **Tip:** NVD enrichment is used by `domainraptor assess list --enrich` to fetch official CVE descriptions and CVSS scores.

---

## Configuration Methods

### Method 1: CLI (Recommended)

```bash
# Set individual keys
domainraptor config set SHODAN_API_KEY your_key_here
domainraptor config set ZOOMEYE_API_KEY your_key_here
domainraptor config set CENSYS_API_TOKEN your_pat_token_here
domainraptor config set VIRUSTOTAL_API_KEY your_key_here
```

### Method 2: Interactive Setup

```bash
domainraptor config init
```

Follow the prompts to enter your API keys.

### Method 3: Environment Variables

```bash
export SHODAN_API_KEY="your_key_here"
export ZOOMEYE_API_KEY="your_key_here"
export CENSYS_API_TOKEN="censys_xxx_yyy"
export VIRUSTOTAL_API_KEY="your_key_here"
```

Add to shell profile for persistence:

```bash
# ~/.bashrc or ~/.zshrc
export SHODAN_API_KEY="AbCdEf123456789GhIjKlMnOpQrStUvWx"
export ZOOMEYE_API_KEY="366C744C-52F4-6AA41-f5CF-1cf8603ff45"
export CENSYS_API_TOKEN="censys_ffgeRyx8_BrN5ne8WzXvTKCpCMSVDAiyY"
```

### Method 4: .env File

Edit `~/.domainraptor/.env`:

```env
SHODAN_API_KEY=AbCdEf123456789GhIjKlMnOpQrStUvWx
ZOOMEYE_API_KEY=366C744C-52F4-6AA41-f5CF-1cf8603ff45
CENSYS_API_TOKEN=censys_ffgeRyx8_BrN5ne8WzXvTKCpCMSVDAiyY
VIRUSTOTAL_API_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
NVD_API_KEY=your_nvd_api_key_here
```

---

## Verifying Configuration

### List Configured Keys

```bash
domainraptor config list
```

Output:

```
                         API Keys Configuration  
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Service       ┃ Key Name           ┃ Status       ┃ Free Tier                    ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Shodan        │ SHODAN_API_KEY     │ ✓ Configured │ 100 queries/month            │
│ ZoomEye       │ ZOOMEYE_API_KEY    │ ✓ Configured │ Subdomain discovery free     │
│ Censys (PAT)  │ CENSYS_API_TOKEN   │ ✓ Configured │ IP lookup free               │
│ VirusTotal    │ VIRUSTOTAL_API_KEY │ ✗ Not set    │ 4 req/min, 500/day           │
└───────────────┴────────────────────┴──────────────┴──────────────────────────────┘
```

### Test API Keys

```bash
# Test all keys
domainraptor config test

# Test specific key
domainraptor config test SHODAN_API_KEY
```

Output:

```
Testing API Keys:

  SHODAN_API_KEY:
    Status: ✓ Valid
    Plan: Developer
    Credits: 95/100

  VIRUSTOTAL_API_KEY:
    Status: ✓ Valid
    Plan: Free
    Quota: 487/500 (daily)

  SECURITYTRAILS_API_KEY:
    Status: ✗ Not configured

  CENSYS_API_KEY:
    Status: ✗ Not configured
```

---

## Feature Availability

### Without API Keys

| Feature | Available |
|---------|-----------|
| Subdomain discovery (crt.sh) | ✓ |
| Subdomain discovery (HackerTarget) | ✓ |
| DNS enumeration | ✓ |
| WHOIS lookup | ✓ |
| SSL/TLS analysis | ✓ |
| HTTP header analysis | ✓ |
| Configuration assessment | ✓ |

### With Shodan API Key

| Feature | Available |
|---------|-----------|
| Port scanning | ✓ |
| Service detection | ✓ |
| Banner grabbing | ✓ |
| CVE correlation | ✓ |
| Host information | ✓ |

### With VirusTotal API Key

| Feature | Available |
|---------|-----------|
| URL reputation | ✓ |
| Domain reputation | ✓ |
| Subdomain enumeration | ✓ |
| Malware analysis | ✓ |

### With SecurityTrails API Key

| Feature | Available |
|---------|-----------|
| Extended subdomain enumeration | ✓ |
| Historical DNS records | ✓ |
| WHOIS history | ✓ |
| Associated domains | ✓ |

---

## Running Without API Keys

Use `--free-only` flag to run with only free data sources:

```bash
domainraptor --free-only discover -T example.com
```

This uses:

- crt.sh (Certificate Transparency)
- HackerTarget
- DNS enumeration
- WHOIS lookup

---

## Security Best Practices

### 1. Protect Your Keys

```bash
# Set restrictive permissions
chmod 600 ~/.domainraptor/.env
```

### 2. Never Commit Keys

Add to `.gitignore`:

```
.env
*.env
.domainraptor/
```

### 3. Use Environment Variables in CI/CD

```yaml
# GitHub Actions
env:
  SHODAN_API_KEY: ${{ secrets.SHODAN_API_KEY }}
  VIRUSTOTAL_API_KEY: ${{ secrets.VIRUSTOTAL_API_KEY }}
```

### 4. Rotate Keys Regularly

- Regenerate API keys periodically
- Immediately rotate if compromised
- Use separate keys for different environments

### 5. Monitor Usage

- Check API quotas regularly
- Set up alerts for unusual usage
- Review access logs when available

---

## Troubleshooting

### Invalid API Key

```
✗ SHODAN_API_KEY: Invalid (Error: Invalid API key)
```

**Solution:** Verify the key is correct and hasn't expired.

### Rate Limited

```
⚠ Rate limit exceeded for VIRUSTOTAL_API_KEY
```

**Solution:** Wait for rate limit reset or upgrade your plan.

### Connection Error

```
✗ SHODAN_API_KEY: Connection error
```

**Solution:** Check internet connection and service status.

---

**← [Database Commands](Commands-Database)** | **Next: [Output Formats](Output-Formats) →**
