# 🔍 Discover Commands

The `discover` command is the primary tool for reconnaissance and asset discovery.

---

## Overview

```bash
domainraptor discover [OPTIONS] COMMAND [ARGS]
```

**Purpose:** Discover domains, subdomains, IPs, certificates, and other assets associated with a target.

---

## Global Discover Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--target` | `-T` | Target domain or IP | Required |
| `--subdomains` | `-s` | Discover subdomains | `True` |
| `--dns` | `-d` | Enumerate DNS records | `True` |
| `--certs` | | Discover SSL certificates | `True` |
| `--ports` | `-p` | Discover open ports | `False` |
| `--whois` | `-w` | Include WHOIS information | `True` |
| `--recursive` | `-r` | Recursively discover assets | `False` |
| `--sources` | | Comma-separated sources to use | All |
| `--exclude` | | Sources to exclude | None |
| `--save/--no-save` | | Save to database | `True` |

---

## Commands

### Full Discovery

Perform comprehensive discovery with all methods:

```bash
domainraptor discover -T example.com
```

With all options enabled:

```bash
domainraptor discover -T example.com --subdomains --dns --certs --ports --whois
```

**Example Output:**

```
ℹ Starting discovery for: example.com
ℹ Mode: standard | Free only: False

╭─────────────────── Scan Summary ───────────────────╮
│ Target: example.com                                │
│ Type: discover                                     │
│ Status: completed                                  │
│ Duration: 42.3s                                    │
│                                                    │
│ Findings:                                          │
│   • Assets: 28                                     │
│   • Services: 6                                    │
│   • Certificates: 15                               │
│   • Vulnerabilities: 0                             │
│   • Config Issues: 0                               │
╰────────────────────────────────────────────────────╯

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

### `discover subdomains`

Discover subdomains only:

```bash
domainraptor discover subdomains example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--sources` | `-s` | Sources to use | All |
| `--wordlist` | `-w` | Custom wordlist for brute force | None |
| `--threads` | `-t` | Number of threads | 10 |
| `--resolve` | `-r` | Resolve discovered subdomains | `True` |

**Examples:**

```bash
# Basic subdomain discovery
domainraptor discover subdomains example.com

# Use specific sources only
domainraptor discover subdomains example.com --sources crt_sh,hackertarget

# Include brute force with custom wordlist
domainraptor discover subdomains example.com -w /path/to/wordlist.txt -t 20

# Without DNS resolution
domainraptor discover subdomains example.com --no-resolve
```

**Example Output:**

```
ℹ Discovering subdomains for: example.com

                    Discovered Subdomains
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Subdomain                  ┃ IP Address      ┃ Source       ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ www.example.com            │ 93.184.216.34   │ crt_sh       │
│ mail.example.com           │ 93.184.216.35   │ crt_sh       │
│ api.example.com            │ 93.184.216.36   │ hackertarget │
│ dev.example.com            │ 93.184.216.37   │ hackertarget │
│ staging.example.com        │ 10.0.0.5        │ shodan       │
│ admin.example.com          │ 93.184.216.38   │ shodan       │
│ portal.example.com         │ 93.184.216.39   │ securitytrails│
│ vpn.example.com            │ 93.184.216.40   │ dns_brute    │
└────────────────────────────┴─────────────────┴──────────────┘

✓ Found 8 subdomains from 5 sources
```

---

### `discover dns`

Enumerate DNS records:

```bash
domainraptor discover dns example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--types` | `-t` | Record types (A,AAAA,MX,NS,TXT,CNAME,SOA) | All |
| `--nameserver` | `-n` | Custom nameserver | System default |

**Examples:**

```bash
# All DNS records
domainraptor discover dns example.com

# Specific record types
domainraptor discover dns example.com --types A,MX,TXT

# Use custom nameserver
domainraptor discover dns example.com -n 8.8.8.8
```

**Example Output:**

```
ℹ Enumerating DNS records for: example.com

                        DNS Records
┏━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Type  ┃ Value                                           ┃
┡━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ A     │ 93.184.216.34                                   │
│ AAAA  │ 2606:2800:220:1:248:1893:25c8:1946              │
│ MX    │ 10 mail.example.com                             │
│ MX    │ 20 mail2.example.com                            │
│ NS    │ ns1.example.com                                 │
│ NS    │ ns2.example.com                                 │
│ TXT   │ "v=spf1 include:_spf.example.com ~all"          │
│ TXT   │ "google-site-verification=abc123..."            │
│ SOA   │ ns1.example.com admin.example.com 2024010101... │
│ CNAME │ www -> example.com                              │
└───────┴─────────────────────────────────────────────────┘

✓ Found 10 DNS records
```

---

### `discover certs`

Discover SSL/TLS certificates from Certificate Transparency logs:

```bash
domainraptor discover certs example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--include-expired` | `-e` | Include expired certificates | `False` |
| `--days` | `-d` | Only certs issued in last N days | All |

**Examples:**

```bash
# Current certificates only
domainraptor discover certs example.com

# Include expired certificates
domainraptor discover certs example.com --include-expired

# Certificates from last 90 days
domainraptor discover certs example.com --days 90
```

**Example Output:**

```
ℹ Discovering certificates for: example.com

                     SSL/TLS Certificates
┏━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━┓
┃ Subject                ┃ Issuer                 ┃ Valid Until ┃ Status  ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━┩
│ *.example.com          │ DigiCert Inc           │ 2025-06-15  │ Valid   │
│ example.com            │ Let's Encrypt          │ 2025-03-20  │ Valid   │
│ mail.example.com       │ Let's Encrypt          │ 2025-04-01  │ Valid   │
│ api.example.com        │ Sectigo Limited        │ 2024-12-31  │ Expired │
└────────────────────────┴────────────────────────┴─────────────┴─────────┘

✓ Found 4 certificates (3 valid, 1 expired)
```

---

### `discover ports`

Discover open ports and services (requires Shodan API key):

```bash
domainraptor discover ports example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--top-ports` | `-t` | Scan top N common ports | 100 |
| `--ports` | `-p` | Specific ports (comma-separated) | None |
| `--service-detection` | `-s` | Detect services | `True` |

**Examples:**

```bash
# Default port scan
domainraptor discover ports example.com

# Scan specific ports
domainraptor discover ports example.com -p 22,80,443,8080,8443

# Top 1000 ports
domainraptor discover ports example.com --top-ports 1000
```

**Example Output:**

```
ℹ Discovering ports for: example.com (93.184.216.34)

                    Open Ports & Services
┏━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┓
┃ Port ┃ Protocol ┃ Service   ┃ Version        ┃ Banner             ┃
┡━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━┩
│ 22   │ tcp      │ ssh       │ OpenSSH 8.9    │ SSH-2.0-OpenSSH... │
│ 80   │ tcp      │ http      │ nginx 1.24.0   │ HTTP/1.1 200 OK    │
│ 443  │ tcp      │ https     │ nginx 1.24.0   │ HTTP/2 200         │
│ 8080 │ tcp      │ http-alt  │ Apache Tomcat  │ HTTP/1.1 404       │
└──────┴──────────┴───────────┴────────────────┴────────────────────┘

✓ Found 4 open ports
```

---

### `discover whois`

Perform WHOIS lookup:

```bash
domainraptor discover whois example.com
```

**Example Output:**

```
ℹ WHOIS lookup for: example.com

                     WHOIS Information
┏━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field              ┃ Value                                  ┃
┡━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Domain Name        │ EXAMPLE.COM                            │
│ Registrar          │ ICANN                                  │
│ Registration Date  │ 1995-08-14                             │
│ Expiration Date    │ 2025-08-13                             │
│ Updated Date       │ 2024-08-14                             │
│ Name Servers       │ ns1.example.com, ns2.example.com       │
│ Status             │ clientDeleteProhibited                 │
│ DNSSEC             │ unsigned                               │
│ Registrant Org     │ Internet Assigned Numbers Authority    │
│ Registrant Country │ US                                     │
└────────────────────┴────────────────────────────────────────┘
```

---

## Advanced Examples

### Deep Discovery with All Sources

```bash
domainraptor -m deep discover -T example.com \
  --subdomains \
  --dns \
  --certs \
  --ports \
  --whois \
  --recursive
```

### Discovery with Specific Sources

```bash
domainraptor discover -T example.com \
  --sources crt_sh,hackertarget,shodan \
  --exclude virustotal
```

### Export Results to JSON

```bash
domainraptor -f json -o discovery.json discover -T example.com
```

### Free Sources Only (No API Keys)

```bash
domainraptor --free-only discover -T example.com
```

---

## Data Sources

| Source | API Key Required | Rate Limit | Data Type |
|--------|-----------------|------------|-----------|
| crt.sh | No | None | Certificates, Subdomains |
| HackerTarget | No | 100/day | Subdomains, DNS |
| DNS | No | None | DNS Records |
| Shodan | Yes | 100/month | Ports, Services, IPs, CVEs |
| ZoomEye | Yes | Subdomain free | Subdomains (host search paid) |
| Censys | Yes (PAT) | IP lookup free | IP info (search paid) |
| VirusTotal | Yes | 500/day | Subdomains, URLs |

---

## ZoomEye Commands

### `discover zoomeye-subdomains`

Discover subdomains using ZoomEye's free domain search API:

```bash
domainraptor discover zoomeye-subdomains example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--limit` | `-l` | Maximum results | 100 |

> 💡 **Note:** This endpoint is **free** and doesn't consume your ZoomEye credits.

---

## Censys Commands

### `discover censys-host`

Look up host information using Censys Platform API v3:

```bash
domainraptor discover censys-host 8.8.8.8
```

**Example Output:**

```
╭────────────────────────────────────────────────────────────╮
│                    Censys Host: 8.8.8.8                    │
╰────────────────────────────────────────────────────────────╯
  Name                dns.google  
  ASN                 AS15169 (GOOGLE)  
  Location            United States  
  Last Seen           2024-01-15  

                        Open Services  
┏━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Port   ┃ Protocol  ┃ Service                              ┃
┡━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 53     │ UDP       │ DNS                                  │
│ 443    │ TCP       │ HTTPS                                │
└────────┴───────────┴──────────────────────────────────────┘
```

> 💡 **Note:** Direct IP lookups are **free**. Certificate/host search requires a paid subscription.

---

**← [Configuration](Configuration)** | **Next: [Assess Commands](Commands-Assess) →**
