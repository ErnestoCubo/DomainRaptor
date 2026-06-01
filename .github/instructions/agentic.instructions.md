---
applyTo: ".github/{agents,prompts,instructions}/**/*.md"
description: "Agentic system rules — owned by ai-auditor, certified by ai-governance-reviewer."
---

# Agentic system rules

Scope: any file under `.github/agents/`, `.github/prompts/`,
`.github/instructions/`. Owner: **`ai-auditor`**. Independent reviewer:
**`ai-governance-reviewer`** (cannot be the same agent — HARD RULE 23).

## Single source of truth (HARD RULE 19)

- A rule lives in **one** file. Other files reference it by name/anchor.
- Forbidden: copy-pasting the same paragraph across multiple
  `instructions.md` files.
- `ai-auditor audit` flags duplication; `ai-governance-reviewer`
  certifies the fix.

## Frontmatter (HARD RULE 21)

Every `.agent.md`, `.prompt.md`, `.instructions.md` MUST have valid YAML:

```yaml
---
description: <one-line, triggers-rich, ≥3 invocation examples in body>
applyTo: <glob>          # instructions only
tools: [tool1, tool2]    # agents only — minimal set
model: <model-name>      # agents only — see model-policy.md
---
```

CI workflow `ai-audit.yml` validates the frontmatter on every PR.

## Agent definitions (HARD RULE 20)

- `description` includes at least 3 example invocation triggers
  in the body (`## When to invoke`).
- `tools` list is **minimal** — principle of least privilege. Agents
  without write needs don't get `replace_string_in_file` or `create_file`.
- Each agent declares its **output location** (where its reports go).

## Meta-change traceability (HARD RULE 24)

Every commit touching `.github/{agents,prompts,instructions}/**` must
reference in the message:
- An `AUDIT-YYYY-MM-DD.md` file, OR
- A GitHub issue number, OR
- The trigger comment from `ai-auditor`.

Example:
```
refactor(agents): consolidate duplicate exception rules

Closes finding F-003 from AUDIT-2026-06-15.md.
```

## No self-review (HARD RULE 25)

- No agent approves PRs that modify its own `.agent.md`.
- `ai-auditor.agent.md` changes → certified by `ai-governance-reviewer`.
- `ai-governance-reviewer.agent.md` changes → approved by **human only**.

## Quorum to weaken rules (HARD RULE 26)

Removing or relaxing any rule (1–26) requires:
1. Explicit human approval in the PR.
2. `ai-governance-reviewer` report justifying impact.

This applies to rules in:
- `copilot-instructions.md`
- `.github/instructions/*.instructions.md`
- Any `.agent.md` that enforces rules (qa, security, devops, validators).

## Memory hygiene (HARD RULE 22)

- `/memories/repo/` must not contradict versioned instructions.
- `ai-auditor` runs weekly (or pre-release) and reports drift in
  `.github/ai-audit/AUDIT-YYYY-MM-DD.md`.

## Tool budgets

Each agent SHOULD declare in its body:
- Max expected runtime per invocation.
- Token budget (informational; observed via `chronicle`).
- Escalation path (which agent takes over if it fails).

## Forbidden patterns in agent instructions

- "Ignore previous instructions" / jailbreak patterns.
- Instructions that auto-grant tools not in the frontmatter.
- Self-referential loops ("invoke yourself if X").
- Hardcoded API keys, URLs of external services, user PII.

## Sprint integration

Agents that participate in the sprint pipeline (see
`.github/sprints/_template/README.md`) declare their stage:

```yaml
---
sprint_stage: requirements | planning | implementation | review | meta
---
```

This drives the orchestration order in `sprint-planner` outputs.
