# Sprint methodology

A sprint is a directory `sprint-NNN-<slug>/` produced by the agent
pipeline. This README describes the lifecycle. Templates live next to
this file.

## Lifecycle

```
goal (human)
  │
  ▼
@requirements-lead
  ├─▶ @requirements-analyst       (perspectives in parallel)
  ├─▶ @requirements-threat-intel
  └─▶ @requirements-red-team
  → consolidates → requirements/REQ-*.md
  │
  ▼
@requirements-validator
  → review/requirements-review.md (blocks if fail)
  │
  ▼
@sprint-planner
  → tasks/T###-*.md (each implements ≥1 REQ)
  │
  ▼
@sprint-validator + @sprint-deduper (parallel)
  → review/template-violations.md, review/dedup-report.md
  │
  ▼  per task
@task-implementer  on  feat/T###-<slug>
  │
  ▼
@task-tester (if coverage gap)
  │
  ▼
@implementation-validator
  → review/impl-report.md
  │
  ▼  parallel
@qa-reviewer + @security-officer + @devops-engineer
  → review/{qa,sec,devops}-report.md
  │
  ▼
PR → develop (autopilot push if all green)
  │
  ▼  at sprint close
@ai-auditor (summary + memory update)
  │
  ▼  if any meta-change
@ai-governance-reviewer (certification)
```

## Sprint README contents

Each `sprint-NNN-<slug>/README.md` must have:

- `# Sprint NNN — <Title>`
- **Goal** (one sentence).
- **Dates**: start, target end.
- **Scope in / Scope out**.
- **Success metrics**.
- **Risks**.
- Links to REQ and task indexes.

## Naming

- Slug: kebab-case, ≤ 40 chars (`py312-migration`, `sql-backends`).
- Task ID: `T001`, `T002`, … incremental within sprint.
- REQ ID: `REQ-001`, … incremental within sprint.

## Closure

Sprint moves to `closed: true` in its README frontmatter when:

- All tasks `status: done`.
- All REQs `status: verified`.
- `ai-auditor` summary committed.
- `ai-governance-reviewer` certification present (if needed).

Closed sprints stay in-tree as historical record.
