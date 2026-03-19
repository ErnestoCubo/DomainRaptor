# 💾 Database Commands

The `db` command manages the local SQLite database for storing scan results.

---

## Overview

```bash
domainraptor db [OPTIONS] COMMAND [ARGS]
```

**Purpose:** Manage stored scans, export data, and maintain the database.

---

## Commands

### `db list`

List stored scans:

```bash
domainraptor db list
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--target` | `-t` | Filter by target | All |
| `--type` | | Filter by scan type | All |
| `--limit` | `-l` | Maximum results | 20 |
| `--format` | `-f` | Output format: table, json | `table` |

**Examples:**

```bash
# List all scans
domainraptor db list

# Filter by target
domainraptor db list --target example.com

# Filter by scan type
domainraptor db list --type discover

# Show more results
domainraptor db list --limit 50

# JSON output
domainraptor db list -f json
```

**Example Output:**

```
                          Stored Scans
┏━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ ID ┃ Target            ┃ Type          ┃ Date             ┃ Assets ┃
┡━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│  1 │ example.com       │ discover      │ 2025-01-15 10:30 │ 24     │
│  2 │ example.com       │ assess_config │ 2025-01-15 11:00 │ 0      │
│  3 │ example.com       │ assess_vulns  │ 2025-01-15 11:15 │ 0      │
│  4 │ api.example.io    │ discover      │ 2025-01-14 09:00 │ 8      │
│  5 │ test.example.org  │ discover      │ 2025-01-13 14:00 │ 12     │
└────┴───────────────────┴───────────────┴──────────────────┴────────┘

ℹ Showing 5 scan(s)
```

---

### `db show`

Show details of a specific scan:

```bash
domainraptor db show <SCAN_ID>
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--format` | `-f` | Output format: table, json, yaml | `table` |
| `--include` | | Include: assets, issues, vulns, all | `all` |

**Examples:**

```bash
# Show scan details
domainraptor db show 1

# Show only assets
domainraptor db show 1 --include assets

# JSON format
domainraptor db show 1 -f json

# YAML format
domainraptor db show 1 -f yaml
```

**Example Output:**

```
ℹ Scan Details: ID 1

╭────────────────── Scan Information ──────────────────╮
│ Scan ID: 1                                           │
│ Target: example.com                                  │
│ Type: discover                                       │
│ Status: completed                                    │
│ Mode: standard                                       │
│ Started: 2025-01-15 10:30:00                         │
│ Completed: 2025-01-15 10:31:15                       │
│ Duration: 75 seconds                                 │
╰──────────────────────────────────────────────────────╯

                     Discovered Assets
┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Type      ┃ Value                    ┃ Source        ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ ip        │ 93.184.216.34            │ dns           │
│ subdomain │ www.example.com          │ crt_sh        │
│ subdomain │ mail.example.com         │ hackertarget  │
│ subdomain │ api.example.com          │ shodan        │
│ ...       │ ...                      │ ...           │
└───────────┴──────────────────────────┴───────────────┘

Total: 24 assets
```

---

### `db delete`

Delete a scan from the database:

```bash
domainraptor db delete <SCAN_ID>
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--force` | `-f` | Delete without confirmation | `False` |

**Examples:**

```bash
# Delete with confirmation
domainraptor db delete 1

# Delete without confirmation
domainraptor db delete 1 --force

# Delete multiple scans
domainraptor db delete 1 2 3 --force
```

**Example Output:**

```
⚠ Delete scan?
  Scan ID: 1
  Target: example.com
  Type: discover
  Date: 2025-01-15 10:30:00
  Assets: 24

Delete this scan? [y/N]: y

✓ Deleted scan ID: 1
```

---

### `db export`

Export a scan to file:

```bash
domainraptor db export <SCAN_ID>
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--output` | `-o` | Output file path | stdout |
| `--format` | `-f` | Format: json, yaml, csv | `json` |

**Examples:**

```bash
# Export to JSON file
domainraptor db export 1 -o scan_1.json

# Export to YAML
domainraptor db export 1 -f yaml -o scan_1.yaml

# Export to CSV
domainraptor db export 1 -f csv -o scan_1.csv

# Export to stdout
domainraptor db export 1
```

**Example Output:**

```
✓ Exported scan 1 to scan_1.json
```

**JSON Export Structure:**

```json
{
  "scan_id": 1,
  "target": "example.com",
  "type": "discover",
  "status": "completed",
  "started_at": "2025-01-15T10:30:00Z",
  "completed_at": "2025-01-15T10:31:15Z",
  "mode": "standard",
  "assets": [
    {
      "type": "subdomain",
      "value": "www.example.com",
      "source": "crt_sh",
      "first_seen": "2025-01-15T10:30:30Z"
    }
  ],
  "services": [],
  "certificates": [],
  "vulnerabilities": [],
  "config_issues": []
}
```

---

### `db prune`

Delete old scans from the database:

```bash
domainraptor db prune
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--days` | `-d` | Delete scans older than N days | 90 |
| `--target` | `-t` | Only prune specific target | All |
| `--keep-latest` | `-k` | Keep N latest scans per target | 1 |
| `--force` | `-f` | Prune without confirmation | `False` |
| `--dry-run` | | Show what would be deleted | `False` |

**Examples:**

```bash
# Delete scans older than 90 days (default)
domainraptor db prune

# Delete scans older than 30 days
domainraptor db prune --days 30

# Keep only the latest 3 scans per target
domainraptor db prune --keep-latest 3

# Prune specific target
domainraptor db prune --target example.com --days 7

# Dry run (preview)
domainraptor db prune --days 30 --dry-run

# Force without confirmation
domainraptor db prune --days 30 --force
```

**Example Output:**

```
ℹ Pruning scans older than 30 days...

Scans to be deleted:
  • example.com: 5 scans
  • api.example.io: 3 scans
  • test.org: 2 scans

Total: 10 scans will be deleted

Continue? [y/N]: y

✓ Pruned 10 scans
ℹ Database size reduced by 2.3 MB
```

---

### `db stats`

Show database statistics:

```bash
domainraptor db stats
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--format` | `-f` | Output format: table, json | `table` |

**Examples:**

```bash
# Show statistics
domainraptor db stats

# JSON format
domainraptor db stats -f json
```

**Example Output:**

```
Database Statistics

  Total scans: 42
  Unique targets: 8
  Watch targets: 3
  Database size: 4.2 MB

Scans by Type:
  discover: 28
  assess_config: 8
  assess_vulns: 4
  assess_outdated: 2

Scans by Target:
  example.com: 15
  api.example.io: 10
  test.example.org: 8
  staging.example.com: 5
  Other: 4

Storage Usage:
  Assets: 2.1 MB (50%)
  Certificates: 1.2 MB (29%)
  Issues: 0.5 MB (12%)
  Other: 0.4 MB (9%)

ℹ Database location: /home/user/.domainraptor/domainraptor.db
```

---

## Database Location

The SQLite database is stored at:

| Platform | Path |
|----------|------|
| Linux | `~/.domainraptor/domainraptor.db` |
| macOS | `~/.domainraptor/domainraptor.db` |
| Windows | `%USERPROFILE%\.domainraptor\domainraptor.db` |

View path:

```bash
domainraptor config path
```

---

## Database Backup

### Manual Backup

```bash
# Copy database file
cp ~/.domainraptor/domainraptor.db ~/backups/domainraptor_$(date +%Y%m%d).db
```

### Automated Backup Script

```bash
#!/bin/bash
# backup_domainraptor.sh

BACKUP_DIR="$HOME/backups/domainraptor"
DB_PATH="$HOME/.domainraptor/domainraptor.db"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"
cp "$DB_PATH" "$BACKUP_DIR/domainraptor_$DATE.db"

# Keep only last 7 backups
ls -t "$BACKUP_DIR"/*.db | tail -n +8 | xargs -r rm
```

### Restore from Backup

```bash
cp ~/backups/domainraptor_20250115.db ~/.domainraptor/domainraptor.db
```

---

## Database Maintenance

### Optimize Database

```bash
# SQLite vacuum (reduces file size)
sqlite3 ~/.domainraptor/domainraptor.db "VACUUM;"
```

### Check Integrity

```bash
sqlite3 ~/.domainraptor/domainraptor.db "PRAGMA integrity_check;"
```

### Reset Database

```bash
# Remove database (WARNING: deletes all data)
rm ~/.domainraptor/domainraptor.db

# DomainRaptor will create a new database on next run
domainraptor db stats
```

---

## Best Practices

1. **Regular Pruning**: Schedule automatic pruning to manage database size
2. **Backup Before Updates**: Backup database before updating DomainRaptor
3. **Export Important Data**: Export critical scan results to external storage
4. **Monitor Size**: Keep an eye on database size with `db stats`
5. **Use Filters**: Use target/type filters when listing to find scans quickly

---

**← [Compare Commands](Commands-Compare)** | **Next: [API Keys](API-Keys) →**
