# 🎯 Scan Modes

DomainRaptor offers different scan modes to balance speed, thoroughness, and stealth.

---

## Available Modes

| Mode | Speed | Thoroughness | Detection Risk | Use Case |
|------|-------|--------------|----------------|----------|
| `quick` | ⚡ Fast | Low | Low | Initial triage |
| `standard` | 🔄 Medium | Medium | Medium | Regular assessments |
| `deep` | 🐢 Slow | High | Higher | Thorough investigation |
| `stealth` | 🐢 Slow | Medium | Minimal | Sensitive targets |

---

## Setting Scan Mode

### Command Line

```bash
domainraptor -m quick discover -T example.com
domainraptor --mode deep discover -T example.com
```

### Configuration File

```yaml
# ~/.domainraptor/config.yaml
scan:
  mode: standard  # Default mode
```

---

## Mode Details

### Quick Mode

Best for: Initial reconnaissance, time-sensitive assessments

```bash
domainraptor -m quick discover -T example.com
```

**Characteristics:**

- Faster execution (typically < 30 seconds)
- Limited data sources
- Lower accuracy
- Minimal API calls

**What it does:**

- Basic DNS lookup
- Quick certificate check
- Limited subdomain enumeration
- No port scanning

**Settings:**

```yaml
quick:
  timeout: 10
  retries: 1
  sources:
    - dns
    - crt_sh
  features:
    subdomains: limited
    dns: basic
    certificates: quick_check
    ports: disabled
    whois: disabled
```

**Example Output:**

```
ℹ Starting quick discovery for: example.com

  Running quick scan... ━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:15

Quick Scan Results:
  • Subdomains found: 5
  • IP addresses: 1
  • Certificates: 2

⚡ Quick scan completed in 15 seconds
ℹ For more thorough results, use: domainraptor -m standard discover -T example.com
```

---

### Standard Mode (Default)

Best for: Regular assessments, day-to-day use

```bash
domainraptor discover -T example.com
# or
domainraptor -m standard discover -T example.com
```

**Characteristics:**

- Balanced speed and thoroughness
- Uses most data sources
- Good accuracy
- Moderate API usage

**What it does:**

- Full DNS enumeration
- Certificate Transparency search
- Multiple subdomain sources
- WHOIS lookup
- Basic security checks

**Settings:**

```yaml
standard:
  timeout: 30
  retries: 3
  sources:
    - dns
    - crt_sh
    - hackertarget
    - shodan (if API key)
    - virustotal (if API key)
  features:
    subdomains: full
    dns: complete
    certificates: full_check
    ports: top_100
    whois: enabled
```

**Example Output:**

```
ℹ Starting discovery for: example.com
ℹ Mode: standard

  Querying sources... ━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:45

╭─────────────────── Scan Summary ───────────────────╮
│ Target: example.com                                │
│ Type: discover                                     │
│ Status: completed                                  │
│ Duration: 45.2s                                    │
│                                                    │
│ Findings:                                          │
│   • Assets: 24                                     │
│   • Services: 5                                    │
│   • Certificates: 8                                │
╰────────────────────────────────────────────────────╯
```

---

### Deep Mode

Best for: Thorough investigations, comprehensive assessments

```bash
domainraptor -m deep discover -T example.com
```

**Characteristics:**

- Most thorough scanning
- Uses all available sources
- Highest accuracy
- Maximum API usage
- Longer execution time

**What it does:**

- Exhaustive DNS enumeration
- All subdomain sources
- Full port scanning
- Historical data lookup
- Recursive discovery
- Advanced security checks

**Settings:**

```yaml
deep:
  timeout: 60
  retries: 5
  sources:
    - dns
    - crt_sh
    - hackertarget
    - shodan (if API key)
    - virustotal (if API key)
    - securitytrails (if API key)
    - censys (if API key)
  features:
    subdomains: exhaustive
    dns: complete_with_history
    certificates: full_with_chain
    ports: all_common (top 1000)
    whois: full_with_history
    recursive: enabled
```

**Example Output:**

```
ℹ Starting deep discovery for: example.com
ℹ Mode: deep | This may take several minutes

  Phase 1: DNS enumeration... ━━━━━━━━━━━━━━━━━━━━━━ 100%
  Phase 2: Subdomain discovery... ━━━━━━━━━━━━━━━━━━ 100%
  Phase 3: Port scanning... ━━━━━━━━━━━━━━━━━━━━━━━━ 100%
  Phase 4: Certificate analysis... ━━━━━━━━━━━━━━━━━ 100%
  Phase 5: Recursive discovery... ━━━━━━━━━━━━━━━━━━ 100%

╭─────────────────── Scan Summary ───────────────────╮
│ Target: example.com                                │
│ Type: discover                                     │
│ Status: completed                                  │
│ Duration: 3m 42s                                   │
│                                                    │
│ Findings:                                          │
│   • Assets: 87                                     │
│   • Services: 23                                   │
│   • Certificates: 34                               │
│   • Related domains: 5                             │
╰────────────────────────────────────────────────────╯
```

---

### Stealth Mode

Best for: Sensitive targets, avoiding detection

```bash
domainraptor -m stealth discover -T example.com
```

**Characteristics:**

- Minimizes detection risk
- Passive reconnaissance primarily
- Longer delays between requests
- Randomized timing
- No active port scanning

**What it does:**

- Passive DNS lookup
- Certificate Transparency only
- No direct connections to target
- Uses only public databases
- Rate-limited requests

**Settings:**

```yaml
stealth:
  timeout: 60
  retries: 1
  delay_between_requests: 5-15s (randomized)
  sources:
    - crt_sh
    - dns (passive only)
  features:
    subdomains: passive_only
    dns: passive
    certificates: ct_logs_only
    ports: disabled
    whois: cached_only
    direct_connection: disabled
```

**Example Output:**

```
ℹ Starting stealth discovery for: example.com
ℹ Mode: stealth | Using passive reconnaissance only

🔇 Stealth mode active:
   • No direct connections to target
   • Using only public databases
   • Randomized request timing

  Passive reconnaissance... ━━━━━━━━━━━━━━━━━━━━━━ 100% 0:02:30

╭─────────────────── Scan Summary ───────────────────╮
│ Target: example.com                                │
│ Type: discover (stealth)                           │
│ Status: completed                                  │
│ Duration: 2m 30s                                   │
│                                                    │
│ Findings (passive only):                           │
│   • Subdomains: 12                                 │
│   • Certificates: 8                                │
│                                                    │
│ ℹ Active scanning disabled in stealth mode        │
╰────────────────────────────────────────────────────╯
```

---

## Mode Comparison

### Discovery Results

| Data Point | Quick | Standard | Deep | Stealth |
|------------|-------|----------|------|---------|
| Subdomains | ~50% | ~80% | ~95% | ~60% |
| DNS Records | Basic | Full | Full + History | Passive |
| Certificates | Current | Current | All (incl. expired) | CT logs |
| Ports | None | Top 100 | Top 1000 | None |
| WHOIS | None | Current | Full + History | Cached |

### Resource Usage

| Resource | Quick | Standard | Deep | Stealth |
|----------|-------|----------|------|---------|
| Time | < 30s | 30s-2m | 2-10m | 1-5m |
| API Calls | Low | Medium | High | Low |
| Network | Low | Medium | High | Minimal |
| Detection Risk | Low | Medium | Higher | Minimal |

---

## Choosing the Right Mode

### Use Quick When

- You need fast initial results
- Limited time available
- Just need a quick overview
- Testing connectivity

### Use Standard When

- Regular security assessments
- Day-to-day reconnaissance
- Good balance needed
- Most common use case

### Use Deep When

- Comprehensive security audit
- Investigating incidents
- Need maximum coverage
- Time is not a constraint

### Use Stealth When

- Target is sensitive
- Avoiding IDS/IPS detection
- Passive recon only
- Bug bounty (respecting scope)

---

## Custom Mode Configuration

Create custom modes in `config.yaml`:

```yaml
scan:
  mode: custom

custom_modes:
  pentest:
    timeout: 45
    retries: 3
    sources:
      - dns
      - crt_sh
      - hackertarget
      - shodan
    features:
      ports: top_500
      whois: enabled

  monitoring:
    timeout: 30
    retries: 2
    sources:
      - dns
      - crt_sh
    features:
      subdomains: standard
      certificates: expiry_check
```

Use custom mode:

```bash
domainraptor -m pentest discover -T example.com
```

---

**← [Output Formats](Output-Formats)** | **Next: [Examples](Examples) →**
