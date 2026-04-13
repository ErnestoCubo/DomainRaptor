# 👁️ Watch Commands

The `watch` command enables continuous monitoring of targets for changes.

---

## Overview

```bash
domainraptor watch [OPTIONS] COMMAND [ARGS]
```

**Purpose:** Monitor targets for changes in assets, certificates, DNS records, and security posture.

---

## Commands

### `watch add`

Add a target to the watch list:

```bash
domainraptor watch add example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--interval` | `-i` | Check interval (1h, 6h, 24h, 7d) | `24h` |
| `--type` | `-t` | Watch type: domain, ip, certificate | `domain` |
| `--notify` | `-n` | Notification channel | None |
| `--tags` | | Comma-separated tags | None |

**Interval Formats:**

| Format | Description |
|--------|-------------|
| `1h` | Every hour |
| `6h` | Every 6 hours |
| `12h` | Every 12 hours |
| `24h` | Daily (default) |
| `7d` | Weekly |

**Examples:**

```bash
# Watch domain daily (default)
domainraptor watch add example.com

# Watch every 6 hours
domainraptor watch add example.com --interval 6h

# Watch IP address specifically
domainraptor watch add 93.184.216.34 --type ip

# Watch certificate expiration
domainraptor watch add example.com --type certificate

# Add tags for organization
domainraptor watch add example.com --tags "production,critical"

# Watch with email notification
domainraptor watch add example.com --notify email:security@example.com

# Watch with Slack webhook
domainraptor watch add example.com --notify webhook:https://hooks.slack.com/xxx
```

**Example Output:**

```
ℹ Adding example.com to watch list (interval: 24h)

  Performing initial scan... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

✓ Now watching: example.com
ℹ Watch ID: watch_a1b2c3d4
ℹ Next check: 2025-01-16 10:30:00

Initial Baseline:
  • Subdomains: 12
  • IP Addresses: 3
  • Certificates: 4
  • Open Ports: 5
```

---

### `watch remove`

Remove a target from the watch list:

```bash
domainraptor watch remove example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--force` | `-f` | Remove without confirmation | `False` |
| `--keep-data` | | Keep historical data | `False` |

**Examples:**

```bash
# Remove with confirmation
domainraptor watch remove example.com

# Force remove without confirmation
domainraptor watch remove example.com --force

# Remove but keep historical data
domainraptor watch remove example.com --keep-data
```

**Example Output:**

```
⚠ Remove example.com from watch list?
  • Watch ID: watch_a1b2c3d4
  • Watching since: 2025-01-01
  • Total checks: 15
  • Historical data will be deleted

Remove? [y/N]: y

✓ Removed example.com from watch list
```

---

### `watch list`

List all watched targets:

```bash
domainraptor watch list
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--tags` | `-t` | Filter by tags | All |
| `--status` | `-s` | Filter by status: active, paused | All |
| `--format` | `-f` | Output format: table, json | `table` |

**Examples:**

```bash
# List all watched targets
domainraptor watch list

# Filter by tag
domainraptor watch list --tags production

# Show only active watches
domainraptor watch list --status active

# JSON output
domainraptor watch list -f json
```

**Example Output:**

```
ℹ Watched Targets:

                            Active Watches
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Target         ┃ Type     ┃ Interval  ┃ Last Check           ┃ Status   ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ example.com    │ domain   │ 24h       │ 2025-01-15 10:30:00  │ Active   │
│ api.example.io │ domain   │ 6h        │ 2025-01-15 14:00:00  │ Active   │
│ 93.184.216.34  │ ip       │ 24h       │ 2025-01-15 08:00:00  │ Active   │
│ test.org       │ cert     │ 7d        │ 2025-01-08 00:00:00  │ Paused   │
└────────────────┴──────────┴───────────┴──────────────────────┴──────────┘

ℹ Total: 4 targets (3 active, 1 paused)
```

---

### `watch run`

Manually run checks on watched targets:

```bash
domainraptor watch run
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--target` | `-t` | Specific target to check | All |
| `--force` | `-f` | Run even if not due | `False` |

**Examples:**

```bash
# Run all due checks
domainraptor watch run

# Check specific target
domainraptor watch run --target example.com

# Force check (ignore schedule)
domainraptor watch run --force
```

**Example Output:**

```
ℹ Running watch checks...

  Checking example.com... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%
  Checking api.example.io... ━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100%

╭─────────────────── Watch Check Results ───────────────────╮
│ Targets checked: 2                                        │
│ Changes detected: 1                                       │
│ New alerts: 1                                             │
╰───────────────────────────────────────────────────────────╯

                        Detected Changes
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Target         ┃ Type     ┃ Change                               ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ example.com    │ NEW      │ New subdomain: staging.example.com   │
└────────────────┴──────────┴──────────────────────────────────────┘
```

---

### `watch pause`

Pause monitoring for a target:

```bash
domainraptor watch pause example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--duration` | `-d` | Pause duration (e.g., 7d, 30d) | Indefinite |

**Examples:**

```bash
# Pause indefinitely
domainraptor watch pause example.com

# Pause for 7 days (auto-resume)
domainraptor watch pause example.com --duration 7d

# Pause for maintenance window
domainraptor watch pause example.com --duration 4h
```

**Example Output:**

```
✓ Paused monitoring for: example.com
ℹ Resume with: domainraptor watch resume example.com
```

---

### `watch resume`

Resume monitoring for a paused target:

```bash
domainraptor watch resume example.com
```

**Example Output:**

```
✓ Resumed monitoring for: example.com
ℹ Next check: 2025-01-16 10:30:00
```

---

### `watch status`

Show detailed status for a watched target:

```bash
domainraptor watch status example.com
```

**Example Output:**

```
ℹ Watch Status: example.com

╭────────────────── Watch Details ──────────────────╮
│ Target: example.com                               │
│ Watch ID: watch_a1b2c3d4                          │
│ Type: domain                                      │
│ Status: Active                                    │
│ Interval: 24h                                     │
├───────────────────────────────────────────────────┤
│ Created: 2025-01-01 00:00:00                      │
│ Last Check: 2025-01-15 10:30:00                   │
│ Next Check: 2025-01-16 10:30:00                   │
│ Total Checks: 15                                  │
├───────────────────────────────────────────────────┤
│ Current State:                                    │
│   • Subdomains: 12                                │
│   • IP Addresses: 3                               │
│   • Certificates: 4                               │
│   • Open Ports: 5                                 │
├───────────────────────────────────────────────────┤
│ Change History:                                   │
│   2025-01-14: New subdomain detected              │
│   2025-01-10: Certificate renewed                 │
│   2025-01-05: New port opened (8080)              │
╰───────────────────────────────────────────────────╯
```

---

## Change Detection Types

| Change Type | Description | Alert Level |
|-------------|-------------|-------------|
| `NEW_SUBDOMAIN` | New subdomain discovered | INFO |
| `REMOVED_SUBDOMAIN` | Subdomain no longer resolves | INFO |
| `NEW_IP` | New IP address detected | INFO |
| `IP_CHANGED` | IP address changed | MEDIUM |
| `NEW_PORT` | New open port detected | MEDIUM |
| `PORT_CLOSED` | Port no longer open | INFO |
| `CERT_EXPIRING` | Certificate expiring soon | HIGH |
| `CERT_EXPIRED` | Certificate has expired | CRITICAL |
| `CERT_RENEWED` | Certificate renewed | INFO |
| `DNS_CHANGED` | DNS record changed | MEDIUM |
| `NEW_VULN` | New vulnerability detected | HIGH/CRITICAL |

---

## Notification Channels

### Email Notifications

```bash
domainraptor watch add example.com --notify email:security@example.com
```

### Webhook/Slack

```bash
domainraptor watch add example.com --notify webhook:https://hooks.slack.com/services/xxx
```

### Multiple Channels

```bash
domainraptor watch add example.com \
  --notify email:security@example.com \
  --notify webhook:https://hooks.slack.com/xxx
```

---

## Automation with Cron

Set up automatic monitoring:

```bash
# Run watch checks every hour
0 * * * * domainraptor watch run >> /var/log/domainraptor.log 2>&1

# Run checks every 6 hours
0 */6 * * * domainraptor watch run >> /var/log/domainraptor.log 2>&1
```

---

## Best Practices

1. **Set Appropriate Intervals**: Use shorter intervals for critical assets
2. **Use Tags**: Organize watches with tags (prod, staging, critical)
3. **Configure Notifications**: Set up alerts for important changes
4. **Regular Review**: Periodically review watch list and adjust
5. **Baseline Updates**: Update baselines after legitimate changes

---

**← [Report Commands](Commands-Report)** | **Next: [Compare Commands](Commands-Compare) →**
