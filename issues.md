# DomainRaptor - GitHub Issues & Project Board

Este documento contiene todas las issues para el tablero Kanban de GitHub.
Copiar cada sección separada por `---` como una issue individual.

---

## 🏷️ Labels (Tags)

Crear estos labels en GitHub antes de crear las issues:

| Label | Color | Description |
|-------|-------|-------------|
| `phase-0` | `#0E8A16` | Phase 0: Bug fixes |
| `phase-1` | `#0E8A16` | Phase 1: Dev environment |
| `phase-2` | `#0E8A16` | Phase 2: CLI structure |
| `phase-3` | `#0E8A16` | Phase 3: Discovery module |
| `phase-4` | `#0E8A16` | Phase 4: Assessment module |
| `phase-5` | `#1D76DB` | Phase 5: Storage |
| `phase-6` | `#1D76DB` | Phase 6: Watch/Monitor |
| `phase-7` | `#1D76DB` | Phase 7: Compare |
| `phase-8` | `#1D76DB` | Phase 8: Reporting |
| `enhancement` | `#A2EEEF` | New feature |
| `bug` | `#D73A4A` | Bug fix |
| `documentation` | `#0075CA` | Documentation |
| `infrastructure` | `#BFD4F2` | CI/CD, tooling |
| `cli` | `#FBCA04` | CLI related |
| `discovery` | `#7057FF` | Discovery module |
| `assessment` | `#FF7619` | Assessment module |
| `storage` | `#B60205` | Storage/Database |

---

## 🎯 Milestones

| Milestone | Due Date | Description |
|-----------|----------|-------------|
| v0.2.0 - Foundation | 2026-03-15 | Core infrastructure and CLI |
| v0.3.0 - Discovery & Assessment | 2026-03-31 | Data collection and security checks |
| v0.4.0 - Persistence | 2026-04-15 | Storage and monitoring |
| v0.5.0 - Reporting | 2026-04-30 | Report generation |
| v1.0.0 - Production | 2026-06-30 | First stable release |

---

# ✅ COMPLETED ISSUES

---

## [Phase 0] Fix IPv6 regex pattern

**Title:** fix: IPv6 regex pattern not matching valid addresses

**Description:**
The IPv6 extraction regex in `regex_module.py` fails to match valid IPv6 addresses due to incorrect pattern.

### Acceptance Criteria

- [ ] Fix IPv6 regex pattern
- [ ] Add test cases for IPv6 validation
- [ ] Verify with edge cases (compressed, full, mixed)

**Labels:** `phase-0`, `bug`
**Milestone:** v0.2.0 - Foundation
**Status:** ✅ DONE

---

## [Phase 0] Fix Shodan API error handling

**Title:** fix: Shodan client crashes on API errors

**Description:**
The Shodan integration crashes when API returns errors instead of handling them gracefully.

### Acceptance Criteria

- [ ] Add try/catch for API errors
- [ ] Return empty results on failure
- [ ] Log errors for debugging

**Labels:** `phase-0`, `bug`
**Milestone:** v0.2.0 - Foundation
**Status:** ✅ DONE

---

## [Phase 0] Fix logging configuration

**Title:** fix: Logging not configurable and inconsistent

**Description:**
Logging module has hardcoded configuration and doesn't respect user settings.

### Acceptance Criteria

- [ ] Make log level configurable
- [ ] Add proper formatting
- [ ] Support file and console output

**Labels:** `phase-0`, `bug`
**Milestone:** v0.2.0 - Foundation
**Status:** ✅ DONE

---

## [Phase 0] Fix main module error handling

**Title:** fix: Main module crashes on invalid input

**Description:**
Main entry point doesn't handle invalid input gracefully.

### Acceptance Criteria

- [ ] Add input validation
- [ ] Return proper exit codes
- [ ] Show helpful error messages

**Labels:** `phase-0`, `bug`
**Milestone:** v0.2.0 - Foundation
**Status:** ✅ DONE

---

## [Phase 1] Setup development environment

**Title:** feat: Configure development environment with Ruff and pyproject.toml

**Description:**
Set up modern Python development environment with linting, formatting, and proper package configuration.

### Features

- Ruff for linting and formatting (replaces black, isort, flake8)
- pyproject.toml for package configuration
- Type hints throughout codebase
- Pre-commit hooks (optional)

### Acceptance Criteria

- [ ] Configure Ruff with sensible defaults
- [ ] Create pyproject.toml with all dependencies
- [ ] Add ruff.toml configuration
- [ ] Ensure `pip install -e .` works

**Labels:** `phase-1`, `infrastructure`, `enhancement`
**Milestone:** v0.2.0 - Foundation
**Status:** ✅ DONE

---

## [Phase 2] Implement Typer CLI framework

**Title:** feat: Replace argparse with Typer + Rich CLI

**Description:**
Implement modern CLI using Typer with Rich for beautiful output. Structure with 5 main workflows.

### CLI Structure

```
domainraptor
├── discover    # Asset discovery
├── assess      # Security assessment
├── watch       # Continuous monitoring
├── compare     # Scan comparison
└── report      # Report generation
```

### Features

- Typer for CLI parsing with auto-completion
- Rich for tables, progress bars, panels
- Colored output with severity indicators
- Help text with examples

### Acceptance Criteria

- [ ] Implement main CLI entry point
- [ ] Create 5 workflow commands
- [ ] Add subcommands for each workflow
- [ ] Rich output formatting
- [ ] Global options (--verbose, --quiet, --output)

**Labels:** `phase-2`, `cli`, `enhancement`
**Milestone:** v0.2.0 - Foundation
**Status:** ✅ DONE

---

## [Phase 3] Implement crt.sh client for certificate transparency

**Title:** feat: Add crt.sh client for subdomain discovery via CT logs

**Description:**
Implement client to query crt.sh (Certificate Transparency logs) for subdomain enumeration. Free, no API key required.

### Features

- Query certificates by domain
- Extract unique subdomains from SAN fields
- Parse certificate metadata (issuer, dates, serial)
- Handle wildcards appropriately

### Acceptance Criteria

- [ ] CrtShClient class with query method
- [ ] Parse JSON response from crt.sh
- [ ] Deduplicate and clean subdomain list
- [ ] Return Asset objects for discovered subdomains
- [ ] Handle rate limiting gracefully

**Labels:** `phase-3`, `discovery`, `enhancement`
**Milestone:** v0.3.0 - Discovery & Assessment
**Status:** ✅ DONE

---

## [Phase 3] Implement DNS resolution client

**Title:** feat: Add DNS client for record resolution

**Description:**
Implement DNS client using dnspython for resolving A, AAAA, MX, NS, TXT, SOA, CNAME records.

### Features

- Resolve multiple record types
- Support custom DNS servers
- Return structured DnsRecord objects
- Parallel resolution for multiple domains

### Acceptance Criteria

- [ ] DnsClient class with resolve method
- [ ] Support for A, AAAA, MX, NS, TXT, SOA, CNAME
- [ ] Configurable timeout and retries
- [ ] Return DnsRecord dataclass instances

**Labels:** `phase-3`, `discovery`, `enhancement`
**Milestone:** v0.3.0 - Discovery & Assessment
**Status:** ✅ DONE

---

## [Phase 3] Implement HackerTarget client

**Title:** feat: Add HackerTarget client for passive reconnaissance

**Description:**
Implement client for HackerTarget free API to discover subdomains and reverse DNS lookups.

### Features

- Host search (subdomains for domain)
- Reverse DNS lookup
- Free tier: 100 requests/day
- No API key required

### Acceptance Criteria

- [ ] HackerTargetClient class
- [ ] Query subdomains for domain
- [ ] Handle rate limiting (100/day)
- [ ] Parse text response format

**Labels:** `phase-3`, `discovery`, `enhancement`
**Milestone:** v0.3.0 - Discovery & Assessment
**Status:** ✅ DONE

---

## [Phase 3] Implement WHOIS client

**Title:** feat: Add WHOIS lookup client

**Description:**
Implement WHOIS client using python-whois for domain registration information.

### Features

- Query domain registration info
- Parse registrar, dates, nameservers
- Calculate days until expiry
- Check DNSSEC status

### Acceptance Criteria

- [ ] WhoisClient class
- [ ] WhoisInfo dataclass for results
- [ ] Handle timezone-aware dates
- [ ] Expiry warnings (30/60/90 days)

**Labels:** `phase-3`, `discovery`, `enhancement`
**Milestone:** v0.3.0 - Discovery & Assessment
**Status:** ✅ DONE

---

## [Phase 3] Create discovery orchestrator

**Title:** feat: Implement discovery orchestrator for parallel execution

**Description:**
Create orchestrator to coordinate multiple discovery clients and aggregate results.

### Features

- Parallel execution with ThreadPoolExecutor
- Progress callbacks for UI updates
- Aggregate and deduplicate results
- Configurable client selection

### Acceptance Criteria

- [ ] DiscoveryOrchestrator class
- [ ] Parallel DNS, crt.sh, HackerTarget, WHOIS
- [ ] Progress reporting
- [ ] Error handling per client
- [ ] Return unified ScanResult

**Labels:** `phase-3`, `discovery`, `enhancement`
**Milestone:** v0.3.0 - Discovery & Assessment
**Status:** ✅ DONE

---

## [Phase 4] Implement SSL/TLS analyzer

**Title:** feat: Add SSL/TLS security analyzer

**Description:**
Implement SSL/TLS analyzer using Python's ssl module to check TLS configuration.

### Security Checks

- TLS protocol versions (1.0, 1.1, 1.2, 1.3)
- Cipher suite strength
- Certificate validity and expiration
- Certificate chain validation

### Acceptance Criteria

- [ ] SSLAnalyzer class
- [ ] Detect deprecated protocols (TLS 1.0/1.1)
- [ ] Flag weak ciphers (RC4, DES, 3DES)
- [ ] Certificate expiry warnings
- [ ] Return ConfigIssue objects

**Labels:** `phase-4`, `assessment`, `enhancement`
**Milestone:** v0.3.0 - Discovery & Assessment
**Status:** ✅ DONE

---

## [Phase 4] Implement HTTP security headers checker

**Title:** feat: Add HTTP security headers analyzer

**Description:**
Check HTTP security headers for best practices compliance.

### Headers Checked

- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

### Also Detects

- Server header information disclosure
- X-Powered-By leakage
- X-AspNet-Version leakage

### Acceptance Criteria

- [ ] HeadersChecker class
- [ ] Check all security headers
- [ ] Identify missing headers
- [ ] Flag weak configurations
- [ ] Detect information disclosure

**Labels:** `phase-4`, `assessment`, `enhancement`
**Milestone:** v0.3.0 - Discovery & Assessment
**Status:** ✅ DONE

---

## [Phase 4] Implement DNS security checker

**Title:** feat: Add DNS security configuration checker

**Description:**
Check DNS security settings including email authentication and DNSSEC.

### Security Checks

- DNSSEC validation
- SPF record and policy analysis
- DMARC record and policy check
- DKIM (common selectors)
- CAA records
- Nameserver redundancy

### Acceptance Criteria

- [ ] DnsSecurityChecker class
- [ ] DNSSEC presence and validity
- [ ] SPF policy analysis (+all, ~all, -all)
- [ ] DMARC policy check (none, quarantine, reject)
- [ ] DKIM selector detection
- [ ] CAA record verification

**Labels:** `phase-4`, `assessment`, `enhancement`
**Milestone:** v0.3.0 - Discovery & Assessment
**Status:** ✅ DONE

---

## [Phase 4] Create assessment orchestrator

**Title:** feat: Implement assessment orchestrator

**Description:**
Create orchestrator to coordinate SSL, headers, and DNS security checks.

### Features

- Sequential or parallel execution
- Progress callbacks
- Aggregate results by severity
- Filter by minimum severity

### Acceptance Criteria

- [ ] AssessmentOrchestrator class
- [ ] Parallel check execution
- [ ] Severity filtering
- [ ] Sort results by severity
- [ ] Return unified ScanResult

**Labels:** `phase-4`, `assessment`, `enhancement`
**Milestone:** v0.3.0 - Discovery & Assessment
**Status:** ✅ DONE

---

# 📋 PLANNED ISSUES

---

## [Phase 5] Implement SQLite storage backend

**Title:** feat: Add SQLite database for scan persistence

**Description:**
Implement SQLite storage to persist scan results, assets, and findings.

### Database Schema

```sql
- scans (id, target, type, started_at, completed_at, status)
- assets (id, scan_id, type, value, parent, source, metadata)
- config_issues (id, scan_id, severity, category, title, description)
- vulnerabilities (id, scan_id, cve_id, severity, title, cvss_score)
```

### Features

- Automatic saving with --save flag (default)
- Skip saving with --no-save flag
- Query historical scans
- Export scan data

### Acceptance Criteria

- [ ] SQLite database initialization
- [ ] Scan CRUD operations
- [ ] Asset storage
- [ ] ConfigIssue storage
- [ ] Migration support

**Labels:** `phase-5`, `storage`, `enhancement`
**Milestone:** v0.4.0 - Persistence
**Status:** 📋 TODO

---

## [Phase 5] Add database CLI commands

**Title:** feat: Implement db management commands

**Description:**
Add CLI commands for database management operations.

### Commands

```
domainraptor db list [--target] [--type] [--limit]
domainraptor db show <scan_id>
domainraptor db delete <scan_id>
domainraptor db export <scan_id> --format json|csv
domainraptor db prune --older-than 30d
domainraptor db backup <path>
```

### Acceptance Criteria

- [ ] List scans with filters
- [ ] Show scan details
- [ ] Delete individual scans
- [ ] Export scan to file
- [ ] Prune old scans
- [ ] Backup database

**Labels:** `phase-5`, `storage`, `cli`, `enhancement`
**Milestone:** v0.4.0 - Persistence
**Status:** 📋 TODO

---

## [Phase 6] Implement watch mode

**Title:** feat: Add continuous monitoring (watch mode)

**Description:**
Implement watch mode for monitoring targets continuously and detecting changes.

### Features

- Add targets to watch list
- Configurable check intervals (1h, 6h, 24h, 7d)
- Change detection between scans
- Alert on new/removed/modified assets

### Commands

```
domainraptor watch add <target> --interval 24h
domainraptor watch remove <target>
domainraptor watch list
domainraptor watch run [--target]
domainraptor watch status
```

### Acceptance Criteria

- [ ] WatchTarget persistence
- [ ] Scheduled scan execution
- [ ] Change detection algorithm
- [ ] Alert generation
- [ ] Run in background (daemon mode)

**Labels:** `phase-6`, `enhancement`
**Milestone:** v0.4.0 - Persistence
**Status:** 📋 TODO

---

## [Phase 7] Implement scan comparison

**Title:** feat: Add scan comparison and diff

**Description:**
Compare scans over time to identify changes in attack surface.

### Features

- Compare two specific scans
- Compare current vs last scan
- Show added/removed/modified assets
- Timeline visualization

### Commands

```
domainraptor compare history <target> --last 5
domainraptor compare scans <scan_id_1> <scan_id_2>
domainraptor compare targets <target_1> <target_2>
domainraptor compare baseline <scan_id> --current <scan_id>
```

### Acceptance Criteria

- [ ] Load historical scans
- [ ] Diff algorithm for assets
- [ ] Change categorization (NEW, REMOVED, MODIFIED)
- [ ] Table and timeline output
- [ ] Export diff as JSON

**Labels:** `phase-7`, `enhancement`
**Milestone:** v0.4.0 - Persistence
**Status:** 📋 TODO

---

## [Phase 8] Implement JSON export

**Title:** feat: Add JSON report export

**Description:**
Export scan results to structured JSON format.

### JSON Structure

```json
{
  "scan": { "id", "target", "type", "timestamp" },
  "summary": { "assets", "issues", "vulns" },
  "assets": [...],
  "config_issues": [...],
  "vulnerabilities": [...]
}
```

### Acceptance Criteria

- [ ] JSON serializer for ScanResult
- [ ] Pretty print option
- [ ] Include metadata
- [ ] Configurable sections

**Labels:** `phase-8`, `enhancement`
**Milestone:** v0.5.0 - Reporting
**Status:** 📋 TODO

---

## [Phase 8] Implement HTML report generation

**Title:** feat: Add HTML report generation with templates

**Description:**
Generate beautiful HTML reports from scan results using Jinja2 templates.

### Features

- Executive summary template
- Technical details template
- Severity color coding
- Charts and statistics
- Exportable to PDF

### Acceptance Criteria

- [ ] Jinja2 template engine
- [ ] Executive summary template
- [ ] Technical report template
- [ ] CSS styling
- [ ] Asset tables and issue lists

**Labels:** `phase-8`, `enhancement`
**Milestone:** v0.5.0 - Reporting
**Status:** 📋 TODO

---

## [Phase 8] Implement Markdown report generation

**Title:** feat: Add Markdown report export

**Description:**
Generate Markdown reports suitable for documentation and wikis.

### Features

- GitHub-flavored Markdown
- Table formatting
- Severity badges
- Collapsible sections

### Acceptance Criteria

- [ ] Markdown generator
- [ ] Summary section
- [ ] Findings tables
- [ ] Remediation section

**Labels:** `phase-8`, `enhancement`
**Milestone:** v0.5.0 - Reporting
**Status:** 📋 TODO

---

## [Phase 8] Implement PDF report generation

**Title:** feat: Add PDF report export

**Description:**
Generate PDF reports from HTML templates.

### Options

- WeasyPrint (pure Python)
- wkhtmltopdf (external dependency)

### Acceptance Criteria

- [ ] HTML to PDF conversion
- [ ] Page headers/footers
- [ ] Table of contents
- [ ] Page numbers

**Labels:** `phase-8`, `enhancement`
**Milestone:** v0.5.0 - Reporting
**Status:** 📋 TODO

---

## [Future] Implement CVE correlation

**Title:** feat: Add CVE lookup and correlation

**Description:**
Query NVD/NIST API to correlate detected software versions with known CVEs.

### Features

- NVD API integration
- Software version detection
- CVE matching
- CVSS score display

### Acceptance Criteria

- [ ] NVD API client
- [ ] Software fingerprinting
- [ ] CVE matching algorithm
- [ ] Vulnerability reporting

**Labels:** `enhancement`
**Milestone:** v1.0.0 - Production
**Status:** 📋 TODO

---

## [Future] Implement Web UI backend

**Title:** feat: Add FastAPI backend for web interface

**Description:**
Create REST API for web interface using FastAPI.

### Endpoints

- `/api/scans` - Scan management
- `/api/targets` - Target management
- `/api/reports` - Report generation
- `/api/auth` - Authentication

### Acceptance Criteria

- [ ] FastAPI application
- [ ] JWT authentication
- [ ] Scan endpoints
- [ ] OpenAPI documentation

**Labels:** `enhancement`
**Milestone:** v1.0.0 - Production
**Status:** 📋 TODO

---

## [Future] Implement Web UI frontend

**Title:** feat: Add React frontend

**Description:**
Create web interface using React + Vite.

### Features

- Dashboard with statistics
- Scan management
- Results visualization
- Report generation

### Acceptance Criteria

- [ ] React application
- [ ] Dashboard page
- [ ] Scan list and details
- [ ] Issue tables
- [ ] Report download

**Labels:** `enhancement`
**Milestone:** v1.0.0 - Production
**Status:** 📋 TODO

---

# 📝 PULL REQUEST

## PR Title

```
feat: DomainRaptor v0.3.0 - Discovery & Assessment modules
```

## PR Description

```markdown
## Summary

This PR implements the complete CLI-based discovery and assessment functionality for DomainRaptor, an open-source cyber intelligence platform.

## Changes

### Phase 0: Bug Fixes
- Fixed IPv6 regex pattern
- Fixed Shodan API error handling
- Fixed logging configuration
- Fixed main module error handling

### Phase 1: Development Environment
- Configured Ruff for linting/formatting
- Created pyproject.toml with modern Python packaging
- Added type hints throughout codebase

### Phase 2: CLI Framework
- Implemented Typer CLI with 5 workflows (discover, assess, watch, compare, report)
- Added Rich for beautiful terminal output
- Progress bars, tables, and colored panels

### Phase 3: Discovery Module
- **crt.sh client**: Certificate Transparency subdomain discovery
- **DNS client**: Resolution for A, AAAA, MX, NS, TXT, SOA, CNAME
- **HackerTarget client**: Passive subdomain enumeration
- **WHOIS client**: Domain registration info with expiry tracking
- **Discovery orchestrator**: Parallel execution with progress reporting

### Phase 4: Assessment Module
- **SSL/TLS analyzer**: Protocol/cipher checking, certificate validation
- **Headers checker**: HSTS, CSP, X-Frame-Options, information disclosure
- **DNS security**: DNSSEC, SPF, DMARC, DKIM, CAA verification
- **Assessment orchestrator**: Coordinated security checks

## Testing

```bash
# Discovery
domainraptor discover -T example.com --no-save
domainraptor discover dns example.com
domainraptor discover whois example.com
domainraptor discover certs example.com
domainraptor discover subdomains example.com

# Assessment
domainraptor assess config example.com --category ssl
domainraptor assess config example.com --category headers
domainraptor assess config example.com --category dns
domainraptor assess -T example.com
```

## Screenshots

### Discovery Output

```
╭─────────────── DNS Records for example.com ───────────────╮
│ Type  │ Value                  │ TTL    │ Priority       │
│ A     │ 93.184.216.34          │ 86400  │ -              │
│ MX    │ mail.example.com       │ 86400  │ 10             │
╰───────────────────────────────────────────────────────────╯
```

### Assessment Output

```
╭────────────── Configuration Issues ──────────────╮
│ ID      │ Severity │ Category │ Title           │
│ DNS-001 │ MEDIUM   │ dns      │ DNSSEC not...   │
│ HDR-001 │ HIGH     │ headers  │ Missing HSTS... │
╰──────────────────────────────────────────────────╯
```

## Dependencies

All using free data sources:

- httpx (HTTP client)
- dnspython (DNS resolution)
- python-whois (WHOIS lookup)
- typer + rich (CLI)

No paid API keys required.

## Next Steps

- Phase 5: SQLite storage
- Phase 6: Watch/monitoring mode
- Phase 7: Scan comparison
- Phase 8: Report generation (JSON, HTML, MD, PDF)

## Checklist

- [x] Code follows project style guidelines
- [x] All new code has type hints
- [x] Commands tested manually
- [ ] Unit tests added (Phase 5)
- [x] Documentation updated (REQUIREMENTS.md roadmap)

```

---

*Generated: March 2026*
*Document for GitHub Issues and Project Board*
