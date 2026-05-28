# 🖥️ Terminal User Interface (TUI)

DomainRaptor ships with a full-screen Textual-based TUI that exposes every command through a navigable sidebar.

---

## Launching the TUI

```bash
domainraptor tui
```

The application loads API keys from `~/.domainraptor/.env` automatically, the same way the CLI does.

---

## Screens

| Screen | Hotkey | Purpose |
|--------|--------|---------|
| 🏠 Dashboard | `d` | At-a-glance stats: scans, recent targets, risk summary |
| 🔍 Discover | `s` | Run subdomain, DNS, certs, ports, WHOIS discovery |
| 🎯 Recon | `r` | Trigger `recon fullscan` workflows |
| 🛡️ Assess | `a` | Vulnerability + configuration assessment |
| 🧨 Exploits | `e` | KEV / EPSS / Exploit-DB enrichment for stored CVEs |
| 🔬 Enrich | `n` | URLScan and other 3rd-party enrichment |
| 📊 Compare | — | Diff two scans side-by-side |
| 👁️ Watch | `w` | Manage monitored targets and intervals |
| 📄 Reports | — | Generate, preview and export reports |
| 💾 Database | `b` | Browse, export and prune stored scans |
| ⚙️ Config | `c` | View / edit API keys |

---

## Global Shortcuts

| Key | Action |
|-----|--------|
| `q` / `Ctrl+C` | Quit |
| ↑ ↓ | Navigate sidebar items |
| `Enter` | Activate sidebar screen |
| `Tab` | Move focus between widgets within a screen |

Each screen exposes its own form controls (target inputs, source toggles, action buttons). Long-running operations stream progress directly into the active panel.

---

## Tips

- The TUI shares the same SQLite database as the CLI — any scan saved from the CLI shows up immediately in the **Database** and **Dashboard** screens (and vice versa).
- The **Exploits** screen is the easiest way to bulk-enrich every CVE in a stored scan and inspect KEV / EPSS percentiles interactively.
- The **Reports** screen previews Markdown and HTML output before writing it to disk.
- If the terminal looks broken after resize, press `Ctrl+L` to redraw.

---

## Requirements

- A terminal with 256-color and Unicode support (most modern terminals: iTerm2, Alacritty, kitty, Windows Terminal, GNOME Terminal).
- Minimum window size **~100 columns × 30 lines** for the full layout.

---

**← [Commands Overview](Home)** | **Next: [Configuration](Configuration) →**
