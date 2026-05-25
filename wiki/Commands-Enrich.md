# 🔬 Enrich Commands

The `enrich` command queries third-party intelligence sources to add context to discovered assets.

---

## Overview

```bash
domainraptor enrich [OPTIONS] COMMAND [ARGS]
```

**Purpose:** Add external intelligence (URLScan.io, etc.) to a domain or existing scan.

> 💡 Looking for CVE-level enrichment (CISA KEV, EPSS, Exploit-DB)? See [`assess exploits`](Commands-Assess#assess-exploits).

---

## Commands

### `enrich urlscan`

Pull public URLScan.io scan history for a domain:

```bash
domainraptor enrich urlscan example.com
```

**Options:**

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--limit` | `-l` | Maximum scans to display | 25 |

**What you get:**

- Total public URLScan scans for the domain
- Unique IPs, ASNs and HTTP server fingerprints seen historically
- Countries the domain has been served from
- Per-scan: indexing date, resolved IP, ASN, server header, country

**Example output:**

```
╭───────── URLScan summary: example.com ─────────╮
│ Total scans     128                            │
│ Unique IPs      6                              │
│ Unique ASNs     3                              │
│ Unique servers  2                              │
│ Countries       US, DE                         │
╰────────────────────────────────────────────────╯

         Recent URLScan scans for example.com
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┓
┃ Indexed    ┃ Domain        ┃ IP            ┃ ASN                ┃ Server    ┃ Country ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━┩
│ 2026-04-12 │ example.com   │ 93.184.216.34 │ AS15133 Edgecast   │ ECAcc     │ US      │
│ 2026-03-30 │ www.exam...   │ 93.184.216.34 │ AS15133 Edgecast   │ ECAcc     │ US      │
└────────────┴───────────────┴───────────────┴────────────────────┴───────────┴─────────┘

✓ 128 scans, 6 unique IPs
```

---

### `enrich all`

Run every available enrichment source for a target in sequence:

```bash
domainraptor enrich all example.com
```

Currently aggregates URLScan (more providers planned). Useful as a single-shot context builder before generating a report.

---

## Notes & Limits

- **URLScan.io** is queried without an API key. Anonymous requests are rate-limited; very large domains may return partial results.
- Enrichment data is **not** persisted to the scan database by default — it is purely informational for the terminal.
- For CVE intelligence (KEV/EPSS/Exploit-DB), use [`assess exploits`](Commands-Assess#assess-exploits), which **does** persist enriched data when `--save` is passed.

---

**← [Assess Commands](Commands-Assess)** | **Next: [Watch Commands](Commands-Watch) →**
