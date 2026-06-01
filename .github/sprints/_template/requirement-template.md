---
id: REQ-NNN
sprint: NNN
title: <imperative, ≤ 80 chars>
sources: [analyst, threat-intel, red-team]   # which specialists raised it
priority: critical | high | medium | low
status: draft | validated | planned | implemented | verified | closed
relates_to: []          # other REQ ids
non_goals: []           # explicit boundaries (REQUIRED key, list may be empty)
acceptance_criteria:
  - <testable statement 1>
  - <testable statement 2>
---

# REQ-NNN — <Title>

## Context

Why this matters now. Link to evidence from the specialists' raw
outputs in `requirements/_*.md`.

## Outcome

What the world looks like after this is done. Observable, not
implementation-detail.

## Constraints

- Compatibility (Python version, deps).
- Performance budget.
- Security / privacy boundaries.

## Out of scope

Cross-reference `non_goals` and expand each item with a sentence.

## Stakeholder views

- **Analyst / business**: …
- **Threat intel**: …
- **Red team**: …

(Filled by `requirements-lead` during consolidation.)
