---
applyTo: "{docs,wiki}/**/*.md"
description: "Documentation rules — wiki layout, command formatting, cross-links."
---

# Docs & Wiki rules

## Where things go

- `wiki/` → published to the GitHub wiki by `.github/workflows/wiki.yml`.
  User-facing docs (install, commands, examples, troubleshooting).
- `docs/` → internal design docs (planning, risk model, social assets).
  Not published.
- `README.md` → project entry point. Keep tight.
- Sprint artifacts → `.github/sprints/`, not `docs/`.

## Command formatting

Always use fenced bash with the `dr` short alias or `domainraptor`:

````markdown
```bash
dr discover example.com --depth 2
```
````

Show env vars inline when relevant:

```bash
SHODAN_API_KEY=… dr discover example.com
```

## Wiki cross-links

GitHub wiki uses page-name links without `.md`:

```markdown
See [Quick Start](Quick-Start) and [Commands: Discover](Commands-Discover).
```

For links to the repo (not wiki), use full repo paths:

```markdown
See [pyproject.toml](https://github.com/ErnestoCubo/DomainRaptor/blob/develop/pyproject.toml).
```

## Style

- Imperative voice in step-by-step guides.
- One H1 per page (the title). Subsections H2/H3.
- No emojis in user-facing docs unless explicitly requested.
- Snippets must run as-is against current `develop`. Test before merging.

## Don't

- Don't duplicate content between `docs/` and `wiki/`. Link instead.
- Don't add a CHANGELOG entry — `release-please` owns it.
- Don't add screenshots without compressing first.
