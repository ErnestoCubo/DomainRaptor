# ⚙️ Configuration

Learn how to configure DomainRaptor for optimal performance.

---

## 📍 Configuration Locations

DomainRaptor uses the following configuration files:

| File | Purpose |
|------|---------|
| `~/.domainraptor/.env` | API keys and secrets |
| `~/.domainraptor/config.yaml` | User preferences |
| `~/.domainraptor/domainraptor.db` | Scan database |

View configuration paths:

```bash
domainraptor config path
```

Output:

```
Configuration Paths:
  Config directory: /home/user/.domainraptor
  Environment file: /home/user/.domainraptor/.env
  Config file: /home/user/.domainraptor/config.yaml
  Database: /home/user/.domainraptor/domainraptor.db
```

---

## 🔑 Managing API Keys

### Setting API Keys

```bash
domainraptor config set <KEY_NAME> <VALUE>
```

**Supported API Keys:**

| Key Name | Service | Purpose |
|----------|---------|---------|
| `SHODAN_API_KEY` | Shodan | Port scanning, service detection |
| `VIRUSTOTAL_API_KEY` | VirusTotal | Malware analysis, URL scanning |
| `SECURITYTRAILS_API_KEY` | SecurityTrails | Subdomain enumeration |
| `CENSYS_API_KEY` | Censys | Certificate search |

**Examples:**

```bash
# Set Shodan API key
domainraptor config set SHODAN_API_KEY AbCdEf123456789GhIjKlMnOpQrStUv

# Set VirusTotal API key
domainraptor config set VIRUSTOTAL_API_KEY a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6

# Set SecurityTrails API key
domainraptor config set SECURITYTRAILS_API_KEY xyz987654321abcdefghijklmnop

# Set Censys API key
domainraptor config set CENSYS_API_KEY qwerty123456asdfgh789012zxcvbn
```

### Viewing API Keys

```bash
# List all configured keys (masked)
domainraptor config list
```

Output:

```
Configured API Keys:
  SHODAN_API_KEY: AbCd****StUv ✓
  VIRUSTOTAL_API_KEY: a1b2****o5p6 ✓
  SECURITYTRAILS_API_KEY: Not configured
  CENSYS_API_KEY: Not configured
```

### Getting a Specific Key

```bash
domainraptor config get SHODAN_API_KEY
```

### Testing API Keys

```bash
# Test all configured keys
domainraptor config test

# Test specific key
domainraptor config test SHODAN_API_KEY
```

Output:

```
Testing API Keys:
  SHODAN_API_KEY: ✓ Valid (Plan: Developer, Credits: 100)
  VIRUSTOTAL_API_KEY: ✓ Valid (Plan: Free, Quota: 500/day)
  SECURITYTRAILS_API_KEY: ✗ Not configured
  CENSYS_API_KEY: ✗ Not configured
```

---

## 🚀 Interactive Setup

Initialize configuration with the interactive wizard:

```bash
domainraptor config init
```

This will:

1. Create the configuration directory
2. Ask for API keys
3. Set default preferences
4. Test connectivity

---

## 📝 Configuration File (config.yaml)

Create or edit `~/.domainraptor/config.yaml`:

```yaml
# DomainRaptor Configuration
version: "1.0"

# Default scan settings
scan:
  mode: standard          # quick, standard, deep, stealth
  timeout: 30             # Request timeout in seconds
  retries: 3              # Number of retries on failure
  save_results: true      # Save to database by default

# Output preferences
output:
  format: table           # table, json, yaml, csv
  color: true             # Enable colored output
  verbose: false          # Verbose output
  banner: true            # Show banner

# Discovery sources
discovery:
  sources:
    - crt_sh              # Certificate Transparency logs
    - hackertarget        # HackerTarget API
    - dns                 # DNS enumeration
    - shodan              # Shodan (requires API key)
    - virustotal          # VirusTotal (requires API key)
    - securitytrails      # SecurityTrails (requires API key)

  excluded_sources: []    # Sources to exclude

# Assessment settings
assessment:
  check_ssl: true
  check_dns: true
  check_headers: true
  min_severity: low       # low, medium, high, critical

# Watch/monitoring settings
watch:
  default_interval: 24h
  notify_on_change: true
  notify_on_new_vuln: true

# Report settings
reports:
  include_remediation: true
  include_history: false
  default_format: html
  output_directory: ~/.domainraptor/reports

# Database settings
database:
  path: ~/.domainraptor/domainraptor.db
  auto_prune: false       # Auto-delete old scans
  prune_days: 90          # Delete scans older than X days
```

---

## 🌐 Environment Variables

You can also use environment variables:

```bash
# Set API keys via environment
export SHODAN_API_KEY="your_key_here"
export VIRUSTOTAL_API_KEY="your_key_here"
export SECURITYTRAILS_API_KEY="your_key_here"
export CENSYS_API_KEY="your_key_here"

# Set default options
export DOMAINRAPTOR_MODE="deep"
export DOMAINRAPTOR_FORMAT="json"
export DOMAINRAPTOR_NO_BANNER="1"
```

Add to your shell profile (`~/.bashrc`, `~/.zshrc`):

```bash
# DomainRaptor configuration
export SHODAN_API_KEY="AbCdEf123456789GhIjKlMnOpQrStUv"
```

---

## 🔒 Security Best Practices

### Protect Your API Keys

1. **Never commit API keys to version control**

   ```bash
   # Add to .gitignore
   echo ".env" >> .gitignore
   echo "*.env" >> .gitignore
   ```

2. **Use environment variables in CI/CD**

   ```yaml
   # GitHub Actions example
   env:
     SHODAN_API_KEY: ${{ secrets.SHODAN_API_KEY }}
   ```

3. **Set appropriate file permissions**

   ```bash
   chmod 600 ~/.domainraptor/.env
   ```

### API Key Security Checklist

- [ ] Store keys in `.env` file, not config.yaml
- [ ] Set restrictive file permissions (600)
- [ ] Never share keys in public channels
- [ ] Rotate keys periodically
- [ ] Use separate keys for testing/production

---

## ⚡ Performance Tuning

### For Faster Scans

```yaml
# config.yaml
scan:
  mode: quick
  timeout: 10
  retries: 1

discovery:
  sources:
    - dns
    - crt_sh
```

### For Thorough Analysis

```yaml
# config.yaml
scan:
  mode: deep
  timeout: 60
  retries: 5

discovery:
  sources:
    - crt_sh
    - hackertarget
    - dns
    - shodan
    - virustotal
    - securitytrails
```

---

**← [Quick Start](Quick-Start)** | **Next: [Discover Commands](Commands-Discover) →**
