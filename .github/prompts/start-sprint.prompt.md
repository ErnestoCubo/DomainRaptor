---
description: Kick off a new sprint via @requirements-lead.
---

# /start-sprint `<goal>`

Invoke the requirements pipeline:

1. Compute next sprint number: highest `NNN` in
   `.github/sprints/sprint-*/` + 1.
2. Ask `@requirements-lead` to plan a sprint with `<goal>`:
   - Slugify the goal (kebab-case, ≤ 40 chars).
   - Create `.github/sprints/sprint-NNN-<slug>/` skeleton.
   - Invoke `requirements-analyst`, `requirements-threat-intel`,
     `requirements-red-team` in parallel.
   - Consolidate into `REQ-*.md`.
3. Hand off to `@requirements-validator`.
4. On validator green: hand off to `@sprint-planner`.
5. On planner output: run `@sprint-validator` + `@sprint-deduper` in
   parallel.

Stop and report any blocker at each step.

## When NOT to use

- Mid-sprint task additions → use `@sprint-task-creator` (manual task)
  instead of restarting requirements.
- Hotfix → branch `fix/<slug>` from `main`, skip sprint flow.
