---
applyTo: ".github/sprints/**/*.md"
description: "Sprint & requirements rules — DRY, template compliance, traceability."
---

# Sprint & Requirements rules

Scope: anything under `.github/sprints/`. Owners: `sprint-planner` for
tasks, `requirements-lead` for requirements. Validators:
`requirements-validator`, `sprint-validator`, `sprint-deduper`.

## File layout

```
.github/sprints/
  _template/
    README.md
    requirement-template.md
    task-template.md
    sec-task-template.md
    devops-task-template.md
    agent-output-template.md
  sprint-NNN-<slug>/
    README.md                  # sprint goal, dates, scope in/out
    requirements/
      REQ-001-<slug>.md        # consolidated by requirements-lead
      _analyst.md              # raw output from requirements-analyst
      _threat-intel.md         # raw from requirements-threat-intel
      _red-team.md             # raw from requirements-red-team
    tasks/
      T001-<slug>.md
      T002-<slug>.md
    review/
      template-violations.md   # sprint-validator
      dedup-report.md          # sprint-deduper
      qa-report.md             # qa-reviewer
      sec-report.md            # security-officer
      devops-report.md         # devops-engineer
      impl-report.md           # implementation-validator
```

## Template compliance (HARD RULE)

Every `REQ-*.md` and `T###-*.md` MUST start with the frontmatter from
the matching `_template/` file. `sprint-validator` rejects PRs that
violate this.

## DRY (HARD RULE)

`sprint-deduper` runs after planning and after every new task:
- Two REQs covering the same outcome → must be merged or one removed.
- Two tasks producing the same artifact → must be merged or sequenced.
- Two requirements specialists raising the same concern → consolidated
  by `requirements-lead`, not left duplicated.

Detection is semantic (not string match). `dedup-report.md` is
mandatory output.

## Traceability

- `T###-*.md` declares `implements: [REQ-001, REQ-002]`.
- `REQ-*.md` declares `sources: [analyst, threat-intel, red-team]`.
- `implementation-validator` rejects PRs whose code changes don't trace
  to at least one REQ via the task frontmatter.

## Branching

- Sprint goal → planning happens on `develop`.
- Each `T###` → branch `feat/T###-<slug>` from `develop`.
- PR back to `develop` when `task-implementer` + reviewers approve.
- `release-please` flows `develop → main`.

## Acceptance criteria

Every REQ and every task has `acceptance_criteria` as a non-empty list
of testable statements. "Tests pass" alone is not enough — the AC must
describe observable behavior.

## Non-goals

Every REQ declares `non_goals: []` (can be empty list, but the key
must exist). Forces the analyst to draw the boundary.

## Status lifecycle

- REQ: `draft → validated → planned → implemented → verified → closed`.
- Task: `todo → in-progress → review → done`.
- Transitions are commits that update the frontmatter. CI enforces
  monotonic progression.

## Sprint closure

`ai-auditor` summarizes the sprint and updates `/memories/repo/` with
learnings. `ai-governance-reviewer` certifies the summary if any
agent definitions changed during the sprint.
