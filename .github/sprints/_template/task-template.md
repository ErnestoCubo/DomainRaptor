---
id: T###
sprint: NNN
title: <imperative, ≤ 80 chars>
implements: [REQ-001]              # ≥ 1 REQ id (traceability)
status: todo | in-progress | review | done
owner: agent | human
depends_on: []                     # other T### ids
estimate: S | M | L | XL
risk: low | medium | high
files_touched:                     # expected paths
  - src/domainraptor/...
  - tests/test_...
---

# T### — <Title>

## Context

One paragraph. Why now, link to the REQ(s) and any prior task.

## Objective

What this task delivers. Single sentence.

## Acceptance criteria

- [ ] Observable behavior 1
- [ ] Observable behavior 2
- [ ] Tests added / modified
- [ ] `uv run pytest -q` green
- [ ] `uv run ruff check .` clean
- [ ] `uv run bandit -r src/` clean for changed paths

## Plan

1. …
2. …
3. …

## Risks & mitigations

- Risk: … → Mitigation: …

## Verification

How `implementation-validator` will check the AC are met.
