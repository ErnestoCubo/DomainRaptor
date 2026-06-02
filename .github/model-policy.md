# Model policy

How agents pick a model. Source of truth — referenced by every
`.agent.md`'s `model:` field.

## Defaults (recommended mix)

| Agent | Model | Rationale |
|---|---|---|
| `requirements-lead` | Opus | Fuses 3 perspectives — high reasoning |
| `requirements-analyst` | Opus | Business/exec POV requires nuance |
| `requirements-threat-intel` | Opus | CTI domain expertise |
| `requirements-red-team` | Opus | Offensive threat modeling |
| `requirements-validator` | Sonnet | Checklist + DRY scan |
| `sprint-planner` | Opus | Architectural decomposition |
| `sprint-validator` | Sonnet | Frontmatter/format checks |
| `sprint-deduper` | Sonnet | Semantic comparison |
| `task-implementer` | Sonnet (default) / Opus (estimate `L/XL` or `risk: high`) | Cost/quality balance |
| `task-tester` | Sonnet | Routine test generation |
| `implementation-validator` | Sonnet | AC traceability; Opus if REQ ambiguous |
| `qa-reviewer` | Opus | Last gate before merge |
| `security-officer` | Opus | Cost of a miss is catastrophic |
| `devops-engineer` | Opus | CI/IaC errors are silent and expensive |
| `ai-auditor` | Opus | Meta-reasoning over the whole system |
| `ai-governance-reviewer` | Opus | Final cut on governance |

Counts: **10 Opus, 5 Sonnet, 1 dynamic**.

## Dynamic escalation (`task-implementer` only)

Read task frontmatter:

```yaml
estimate: S | M | L | XL
risk: low | medium | high
```

Rules:

- `estimate ∈ {S, M}` AND `risk ∈ {low, medium}` → **Sonnet**.
- `estimate ∈ {L, XL}` OR `risk == high` → **Opus**.

## Manual override

User may force a model per invocation:

```
@security-officer --model sonnet quick-scan src/discovery/
```

This bypasses the default. Override is logged but not blocked.
Documented for iteration speed; not a permanent reassignment.

## Cross-vendor

Not used today. All-Anthropic for simplicity. Reconsider after 3
sprints based on `chronicle` data (success rate, latency, cost).

## Changes to this policy

Modifying this file requires:

1. PR with rationale.
2. `ai-auditor audit` (impact on agent fleet).
3. `ai-governance-reviewer` certification.
4. Human approval.
