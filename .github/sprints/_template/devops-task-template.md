---
id: T###
sprint: NNN
title: <imperative, ≤ 80 chars>
type: devops
implements: [REQ-NNN]
status: todo | in-progress | review | done
owner: devops-engineer
depends_on: []
estimate: S | M | L | XL
risk: low | medium | high
impacts: [ci | release | runtime | infra | observability]
files_touched: []
---

# T### — <Title> (devops)

## Operational impact

- Affected env(s): dev / CI / prod.
- Downtime expected: yes / no.
- Blast radius: …
- Reversibility: instant / minutes / hours.

## Plan

1. …
2. …
3. …

## Verification

- [ ] CI matrix passes on all declared Python versions.
- [ ] Local script equivalent updated (DRY with CI).
- [ ] Reproducibility: `uv sync --locked` works on a clean machine.
- [ ] Logs/metrics for the new path documented.

## Rollback plan

Exact steps + commands. If migration, downgrade path.

## Observability

- New log lines: …
- New metrics: …
- Alert rules updated: yes / no.
