# AI Integration Plan

Status: **PLAN ONLY — not implemented yet.**
Owner: DomainRaptor core
Target version: v0.7.0 (proposal)

This document describes how Large Language Models (LLMs) will be integrated
into DomainRaptor, starting with the reporting subsystem. The goal is to
augment, not replace, the deterministic risk algorithm and the raw evidence
collected during scans.

> ⚠ Scope clarification: this document only plans the work. No production
> code is added in this iteration. The deterministic flows (`discover`,
> `assess`, `recon`, `report`) continue to work exactly the same with the AI
> features disabled.

---

## 1. Goals

Three reporting-time AI features, delivered incrementally:

1. **Executive Summary** — Natural-language summary of the scan results
   aimed at non-technical stakeholders. Length-bounded, fact-grounded on the
   structured report data.
2. **Risk Narrative** — Explains *why* the risk score is what it is, calling
   out the top contributors (KEV-listed CVEs, EPSS spikes, public exploits,
   misconfigurations). Provides context the numeric breakdown alone cannot.
3. **Hardening Recommendations** — Tailored, prioritised remediation
   guidance derived from the actual findings (vulnerabilities, missing
   headers, weak TLS, exposed services, public exploits available).

Out of scope for v0.7.0:

- Autonomous decision-making / agentic loops.
- Automatic exploitation, payload generation, or offensive content.
- Replacing the deterministic risk algorithm — AI output is **descriptive**,
  not authoritative.

---

## 2. Non-Negotiable Principles

| Principle | Rationale |
|-----------|-----------|
| **Opt-in only** | AI calls must require `--with-ai` and a configured provider. Default scans stay 100% local + deterministic. |
| **Grounded on structured data** | LLM prompts receive the report dict (vulns, KEV/EPSS/exploit refs, config issues, risk breakdown). No raw web text, no hallucinated CVE IDs. |
| **No PII / secret leakage** | API keys, internal hostnames and tokens captured during scans must never reach the provider. A redaction layer runs before serialization. |
| **Reproducible** | The exact prompt + provider + model + response are persisted alongside the report so reviewers can audit the output. |
| **Bounded cost** | Per-report token budget enforced (default 4k input / 1k output). Refuse to call provider if estimated cost exceeds budget. |
| **Provider-agnostic** | A thin `BaseLlmClient` abstraction; ship at least one cloud provider (OpenAI or Anthropic) and one local provider (Ollama). |
| **Graceful degradation** | If the AI call fails, the deterministic report is still produced — the AI sections are simply omitted with a notice. |

---

## 3. Architecture

```
src/domainraptor/ai/
├── __init__.py
├── base.py              # BaseLlmClient ABC: complete(prompt, *, max_tokens) -> LlmResponse
├── providers/
│   ├── __init__.py
│   ├── openai_client.py
│   ├── anthropic_client.py
│   ├── azure_openai_client.py
│   └── ollama_client.py
├── prompts/
│   ├── executive_summary.md
│   ├── risk_narrative.md
│   └── hardening_recommendations.md
├── redaction.py         # strips API keys, internal IPs, employee names
├── budget.py            # token estimation + per-report cap
├── cache.py             # scan_id -> AI output cache (SQLite, reusable)
└── orchestrator.py      # AiReporter: builds prompts, calls provider, returns sections
```

### Data flow

```
ScanResult (DB) ──► _build_report_data ──► report dict
                                              │
                                              ▼
                                     redaction.redact(dict)
                                              │
                                              ▼
                                AiReporter.generate(sections=[...])
                                              │
                  ┌───────────────────────────┼─────────────────────────────┐
                  ▼                           ▼                             ▼
       prompts/executive_summary    prompts/risk_narrative      prompts/hardening_recs
                  │                           │                             │
                  └─────────► BaseLlmClient.complete() ◄────────────────────┘
                                              │
                                              ▼
                                   ai_sections: dict[str, str]
                                              │
                                              ▼
                       merged into report data, rendered by _format_*
```

---

## 4. CLI / Configuration Surface

### New flag

```bash
domainraptor report generate <target> --with-ai
domainraptor report generate <target> --with-ai --ai-sections summary,risk
```

`--ai-sections` accepts a comma-separated subset of
`summary | risk | hardening`. Default is all three.

### New environment variables

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `DR_LLM_PROVIDER` | yes (if `--with-ai`) | `openai` | `openai`, `anthropic`, `azure_openai`, `ollama` |
| `DR_LLM_MODEL` | no | provider-specific | e.g. `gpt-4o-mini`, `claude-3-5-haiku-20241022`, `llama3.1:8b` |
| `DR_LLM_API_KEY` | yes (cloud providers) | — | Provider API key |
| `DR_LLM_API_BASE` | no | — | For Azure / Ollama / self-hosted |
| `DR_LLM_MAX_INPUT_TOKENS` | no | `4000` | Per-section input cap |
| `DR_LLM_MAX_OUTPUT_TOKENS` | no | `1000` | Per-section output cap |
| `DR_LLM_REDACT` | no | `true` | Disable only for offline / test data |

### `AppConfig` additions

```python
@dataclass
class LlmConfig:
    enabled: bool = False
    provider: str = "openai"
    model: str | None = None
    api_key: str | None = None
    api_base: str | None = None
    max_input_tokens: int = 4000
    max_output_tokens: int = 1000
    redact: bool = True
```

---

## 5. Prompt Contracts

All prompts are deterministic templates with strict input schemas. Each
prompt MUST:

1. Restate the constraint: *"Use ONLY the JSON data provided. Do not invent
   CVE IDs, hostnames or product versions."*
2. Specify the output format (Markdown, bounded length, sectioned).
3. Include a refusal clause for unsafe requests (e.g. "do not produce
   working exploit code, only mitigation guidance").

### 5.1 Executive Summary

- Inputs: `target`, `risk_assessment`, `summary` counts, top 5 findings.
- Output: 3–5 paragraphs, neutral tone, no jargon.

### 5.2 Risk Narrative

- Inputs: `risk_assessment` (score, breakdown, top_factors, all_factors),
  list of KEV/EPSS≥0.5 vulnerabilities, exploit_refs with sources.
- Output: Markdown with sections "Why this score", "Most urgent items",
  "What lowers the score".

### 5.3 Hardening Recommendations

- Inputs: vulnerabilities (id, severity, exploit_refs, KEV/EPSS),
  config_issues (id, category, current_value, recommended_value),
  services summary, DNS/TLS findings.
- Output: Numbered list grouped by severity. Each item: *finding → impact →
  concrete remediation step → effort estimate*.
- Explicit instruction: *no offensive payloads, no exploitation walkthroughs*.

---

## 6. Safety Controls

1. **Redaction** (`ai/redaction.py`):
   - Strip `*_api_key`, `token`, `password`, `Authorization` substrings.
   - Replace internal RFC1918 IPs and ASN-internal hostnames with placeholders.
   - Optional `--ai-redact-targets` to replace public domains with `target-1`.

2. **Budget** (`ai/budget.py`):
   - Estimate tokens via provider tokenizer (fall back to `len(text) / 4`).
   - Refuse the call if estimated cost > configured cap; emit warning.

3. **Output validation**:
   - Reject responses that contain CVE IDs not present in the input.
   - Reject responses exceeding `max_output_tokens`.
   - Reject responses containing exploitation code patterns
     (e.g. shellcode markers, `msfvenom`, raw payloads).

4. **Audit trail**:
   - Persist `(scan_id, section, provider, model, prompt_hash, response,
     created_at)` in a new `ai_report_sections` SQLite table.
   - Re-running `report generate --with-ai --use-cache` skips the LLM call.

---

## 7. Phasing

| Phase | Deliverable | Acceptance |
|-------|-------------|-----------|
| **Phase 1** | `ai/` skeleton, `BaseLlmClient`, OpenAI + Ollama providers, executive summary prompt, `--with-ai` flag, redaction, budget, cache. | `report generate example.com --with-ai` produces a summary section; deterministic report unchanged when flag is absent. |
| **Phase 2** | Risk narrative prompt + integration into Markdown and HTML renderers. | Risk section appears with cited top factors; absent if `--ai-sections` excludes `risk`. |
| **Phase 3** | Hardening recommendations prompt, output validator, anthropic + azure providers, cache table. | Recommendations render with prioritisation; validator blocks invented CVEs in tests. |

Each phase ships independently behind the `--with-ai` flag. No phase
modifies the deterministic risk algorithm.

---

## 8. Testing Strategy

- Unit tests with a `FakeLlmClient` that returns canned responses.
- Snapshot tests for the prompt assembly (input dict → final prompt string).
- Redaction tests with synthetic secrets and RFC1918 addresses.
- Validator tests asserting rejection of hallucinated CVE IDs.
- Integration test (skipped by default, requires `DR_LLM_API_KEY`) running
  end-to-end against a small fixture scan.

---

## 9. Open Questions

1. Should hardening recommendations be persisted as actionable
   `RemediationTask` entities in the DB to enable progress tracking across
   scans? (Likely yes, but out of scope for v0.7.0.)
2. Multi-language output — accept `--ai-language es|en` in Phase 2?
3. Streaming output for interactive runs vs. batch render — start with
   batch only.
4. Vendor lock-in for tokenizer accuracy: use `tiktoken` for OpenAI;
   character-based estimate for others; revisit in Phase 3.

---

## 10. Explicit Non-Goals

- Generating exploit code, payloads or offensive tooling.
- Replacing the deterministic `calculate_risk_level` function.
- Sending raw scan artefacts (TLS chains, full HTTP bodies) to providers.
- Background "always-on" AI analysis — every call is user-initiated.
