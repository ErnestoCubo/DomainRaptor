# DomainRaptor Manual Testing Report

**Date:** 2026-03-19  
**Version:** 0.2.0  
**Target Domain:** hertek.nl  
**Tester:** Automated Testing Agent

---

## Executive Summary

Comprehensive manual testing of all DomainRaptor CLI functionalities was performed against the live domain `hertek.nl`. The tool demonstrates solid core functionality for domain reconnaissance and security assessment, with some areas requiring improvement.

### Overall Status: ✅ Functional (with minor issues)

| Category | Status | Notes |
|----------|--------|-------|
| discover | ✅ Working | Core functionality solid |
| assess | ✅ Working | Config and vuln checks operational |
| report | ⚠️ Partial | Uses placeholder data |
| db | ✅ Working | Persistence and export functional |
| compare | ⚠️ Partial | Some commands use placeholder data |
| watch | ❌ Not Persisting | Watch list not persisted |

---

## Detailed Test Results

### 1. DISCOVER Commands

#### 1.1 `discover dns`

**Status:** ✅ Working

```bash
domainraptor discover dns hertek.nl
```

**Results:**

- Found 14 DNS records
- Record types: A, MX, NS (4), TXT (7), SOA
- A record: 185.36.72.228
- MX: filter.oudenaller.nl (priority 10)
- NS: ns01-ns04.oudenaller.nl
- TXT: SPF, DMARC, domain verification keys
- SOA: ns01.oudenaller.nl

**Edge Cases:**

- ✅ Non-existent domain: Shows "Domain does not exist" message
- ✅ Handles DNS timeouts gracefully

---

#### 1.2 `discover subdomains`

**Status:** ✅ Working

```bash
domainraptor discover subdomains hertek.nl
```

**Results:**

- Found 17 unique subdomains from crt.sh
- HackerTarget: Rate limited (free tier)
- Subdomains include: www, mail, remote, citrix, owa, tracking, staging, etc.

---

#### 1.3 `discover whois`

**Status:** ⚠️ Working (minor bug)

```bash
domainraptor discover whois hertek.nl
```

**Results:**

- Domain registered: 1998-03-19
- Registrar: Registrar.eu
- Contact email retrieved correctly

**Known Issue:**

- Nameservers field incorrectly includes "creation, updated" strings mixed with actual nameservers

---

#### 1.4 `discover ports`

**Status:** ⚠️ Limited Output

```bash
domainraptor discover ports hertek.nl
```

**Results:**

- Command runs without errors
- Limited/no port data returned
- May depend on Shodan API quota or target visibility

---

#### 1.5 `discover --target` (Full Scan)

**Status:** ✅ Working

```bash
domainraptor discover --target hertek.nl
```

**Results:**

- Total Assets Found: 18
- Certificate Transparency: 627 certificates
- Rate limiting handled gracefully (VirusTotal, HackerTarget)
- Proper timeout handling for external services

---

### 2. ASSESS Commands

#### 2.1 `assess --target`

**Status:** ✅ Working

```bash
domainraptor assess --target hertek.nl
```

**Results:**

- Config Issues Found: 9
- Categories: DNS (3), Headers (6)

---

#### 2.2 `assess config`

**Status:** ✅ Working

```bash
domainraptor assess config hertek.nl
```

**Results:**

| ID | Severity | Description |
|----|----------|-------------|
| DNS-001 | Medium | DNSSEC not enabled |
| DNS-021 | Low | DMARC policy set to none |
| DNS-040 | Low | Missing CAA records |
| HDR-002 | Medium | Missing Content-Security-Policy |
| HDR-003 | Low | Missing X-Content-Type-Options |
| HDR-004 | Low | Missing X-Frame-Options |
| HDR-005 | Low | Missing X-XSS-Protection |
| HDR-006 | Low | Missing Referrer-Policy |
| HDR-008 | Low | Missing Permissions-Policy |

---

#### 2.3 `assess vulns`

**Status:** ✅ Working

```bash
domainraptor assess vulns hertek.nl
```

**Results:**

- No vulnerabilities found for target
- Command executes correctly

---

### 3. REPORT Commands

#### 3.1 `report generate`

**Status:** ⚠️ Uses Placeholder Data

```bash
domainraptor report generate hertek.nl -f json -o /tmp/report.json
domainraptor report generate hertek.nl -f html -o /tmp/report.html
```

**Results:**

- Files are created successfully
- Both JSON and HTML formats work
- **Issue:** Report contains placeholder/example data instead of actual scan results from database

---

#### 3.2 `report list`

**Status:** ⚠️ Uses Placeholder Data

```bash
domainraptor report list
```

**Results:**

- Shows example/hardcoded data
- Does not reflect actual stored scans

---

### 4. DB Commands

#### 4.1 `db list`

**Status:** ✅ Working

```bash
domainraptor db list
```

**Results:**

- Shows 20+ stored scans
- Columns: ID, Target, Type, Status, Issues, Date
- **Note:** Assets column shows 0 even when discover found assets (persistence issue)

---

#### 4.2 `db show`

**Status:** ✅ Working

```bash
domainraptor db show 25
```

**Results:**

- Displays scan metadata correctly
- Shows: Target, Type, Status, Duration, Issue counts

**Edge Cases:**

- ✅ Non-existent ID: Shows "Scan X not found" error

---

#### 4.3 `db export`

**Status:** ✅ Working

```bash
domainraptor db export 25 -o /tmp/scan.json
```

**Results:**

- Exports scan data with config issues
- Includes remediation recommendations
- JSON structure is well-formed

---

### 5. COMPARE Commands

#### 5.1 `compare scans`

**Status:** ⚠️ Limited Output

```bash
domainraptor compare scans 24 25
```

**Results:**

- Command executes without errors
- Shows "Comparison complete" but no diff output

---

#### 5.2 `compare history`

**Status:** ⚠️ Placeholder Data

```bash
domainraptor compare history hertek.nl
```

**Results:**

- Shows comparison table with changes
- **Issue:** Data appears to be placeholder (api-v2, old-api subdomains)

---

#### 5.3 `compare targets`

**Status:** ⚠️ Placeholder Data

```bash
domainraptor compare targets hertek.nl example.com
```

**Results:**

- Displays comparison table
- **Issue:** Metrics are placeholder values, not real data

---

#### 5.4 `compare baseline`

**Status:** ✅ Working

```bash
domainraptor compare baseline hertek.nl --baseline 25
```

**Results:**

- Correctly reports "Target matches baseline (no deviations)"

---

### 6. WATCH Commands

#### 6.1 `watch add`

**Status:** ❌ Not Persisting

```bash
domainraptor watch add hertek.nl
```

**Results:**

- Shows "Now watching: hertek.nl"
- Sets next check time
- **Issue:** Target not persisted - subsequent `watch list` shows empty

---

#### 6.2 `watch list`

**Status:** ✅ Working (but empty due to persistence issue)

```bash
domainraptor watch list
```

**Results:**

- Shows "No targets being watched"

---

#### 6.3 `watch run`

**Status:** ✅ Working

```bash
domainraptor watch run
```

**Results:**

- Shows "No targets due for checking"

---

### 7. Edge Cases & Error Handling

| Test Case | Result | Notes |
|-----------|--------|-------|
| Non-existent domain | ✅ Pass | "Domain does not exist" |
| Invalid scan ID | ✅ Pass | "Scan X not found" |
| Without API keys | ✅ Pass | Works with reduced functionality |
| Rate limiting | ✅ Pass | Shows informative messages |
| DNS timeouts | ✅ Pass | Handles gracefully |

---

## Identified Issues (Priority Order)

### High Priority

1. **Report commands use placeholder data** - `report generate` and `report list` don't use actual scan data from database

### Medium Priority

2. **Watch list not persisted** - `watch add` doesn't save targets persistently
2. **Assets not stored in database** - `db list` shows 0 assets even after discover finds them
3. **Compare commands use placeholder data** - `compare history` and `compare targets` show fake data

### Low Priority

5. **WHOIS nameservers parsing bug** - Includes "creation, updated" in nameservers field
2. **Port discovery limited output** - May be Shodan API limitation
3. **Compare scans no output** - Shows "complete" but no actual diff

---

## Recommendations

1. **Immediate:** Fix report generation to pull actual data from database
2. **Short-term:** Implement watch target persistence (SQLite or file-based)
3. **Short-term:** Fix asset persistence in discover commands
4. **Medium-term:** Implement real comparison logic for compare commands
5. **Low priority:** Fix WHOIS parsing edge case

---

## Test Environment

- **OS:** Linux
- **Python:** 3.x (venv)
- **API Keys:** VirusTotal, Shodan (provided)
- **Network:** Standard connectivity
- **Database:** SQLite (default location)

---

## Conclusion

DomainRaptor v0.2.0 demonstrates solid core functionality for domain reconnaissance and security assessment. The `discover` and `assess` commands work reliably and provide valuable security insights. Database operations are functional for storing and exporting scan results.

The main areas requiring attention are:

- Report generation integration with actual scan data
- Watch list persistence
- Compare commands real data integration

The tool handles edge cases and errors gracefully, providing informative messages to users.
