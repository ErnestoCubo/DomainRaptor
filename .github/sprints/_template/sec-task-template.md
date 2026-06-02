---
id: T###
sprint: NNN
title: <imperative, ≤ 80 chars>
type: security
implements: [REQ-NNN]
status: todo | in-progress | review | done
owner: security-officer
depends_on: []
estimate: S | M | L | XL
risk: low | medium | high
stride: [S, T, R, I, D, E]         # which STRIDE categories apply
files_touched: []
---

# T### — <Title> (security)

## Threat model (STRIDE)

| Category | Threat | Likelihood | Impact | Control |
|---|---|---|---|---|
| Spoofing | … | L/M/H | L/M/H | … |
| Tampering | … | … | … | … |
| Repudiation | … | … | … | … |
| Information disclosure | … | … | … | … |
| Denial of service | … | … | … | … |
| Elevation of privilege | … | … | … | … |

## Control(s) to implement

What we will add / change to mitigate.

## Compensating controls

What stays mitigated by existing controls (with reference).

## Verification

- [ ] Bandit clean on changed paths.
- [ ] Security test that demonstrates the control works.
- [ ] `uv pip audit` clean.
- [ ] If logging changed: redaction verified by test.

## Rollback plan

How to revert if the control breaks production behavior.
