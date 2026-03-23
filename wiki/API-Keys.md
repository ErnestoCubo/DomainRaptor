# 🔑 API Keys Setup

Configure API keys to unlock the full potential of DomainRaptor.

---

## Overview

DomainRaptor integrates with multiple security services. While basic functionality works without API keys, configuring them enables:

- More data sources
- Higher rate limits
- Additional features
- Better accuracy

---

## Supported Services

| Service | Required | Free Tier | Features |
|---------|----------|-----------|----------|
| **Shodan** | Optional | ✓ | Port scanning, service detection, CVE lookup |
| **VirusTotal** | Optional | ✓ | Malware analysis, URL reputation, subdomain enumeration |
| **SecurityTrails** | Optional | ✓ | Historical DNS, subdomain enumeration |
| **Censys** | Optional | ✓ | Certificate search, host discovery |
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

### SecurityTrails

1. Go to [https://securitytrails.com/](https://securitytrails.com/)
2. Create a free account
3. Navigate to **API** section
4. Generate your API key

**Free tier includes:**

- 50 queries/month
- Subdomain enumeration
- Basic DNS history

```bash
domainraptor config set SECURITYTRAILS_API_KEY xyz987654321abcdefghijklmnopqrstuvwxyz
```

### Censys

1. Go to [https://search.censys.io/register](https://search.censys.io/register)
2. Create a free account
3. Navigate to **Account** → **API**
4. Copy your API ID and Secret

**Free tier includes:**

- 250 queries/month
- Certificate search
- Host search

```bash
domainraptor config set CENSYS_API_KEY your_api_id:your_api_secret
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
domainraptor config set VIRUSTOTAL_API_KEY your_key_here
domainraptor config set SECURITYTRAILS_API_KEY your_key_here
domainraptor config set CENSYS_API_KEY your_key_here
```

### Method 2: Interactive Setup

```bash
domainraptor config init
```

Follow the prompts to enter your API keys.

### Method 3: Environment Variables

```bash
export SHODAN_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
export SECURITYTRAILS_API_KEY="your_key_here"
export CENSYS_API_KEY="your_key_here"
```

Add to shell profile for persistence:

```bash
# ~/.bashrc or ~/.zshrc
export SHODAN_API_KEY="AbCdEf123456789GhIjKlMnOpQrStUvWx"
export VIRUSTOTAL_API_KEY="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
```

### Method 4: .env File

Edit `~/.domainraptor/.env`:

```env
SHODAN_API_KEY=AbCdEf123456789GhIjKlMnOpQrStUvWx
VIRUSTOTAL_API_KEY=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0
SECURITYTRAILS_API_KEY=xyz987654321abcdefghijklmnopqrstuvwxyz
CENSYS_API_KEY=api_id:api_secret
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
Configured API Keys:
  SHODAN_API_KEY: AbCd****StUv ✓
  VIRUSTOTAL_API_KEY: a1b2****s9t0 ✓
  SECURITYTRAILS_API_KEY: Not configured
  CENSYS_API_KEY: Not configured
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
