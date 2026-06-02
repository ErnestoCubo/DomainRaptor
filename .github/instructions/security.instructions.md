---
applyTo: "{src/**/*.py,pyproject.toml,uv.lock,.github/workflows/**,infra/**,Dockerfile,docker-compose*.yml,*.tf}"
description: "Security rules — owned by security-officer. Hot paths, secrets, deps, IaC."
---

# Security rules

Owner: **`security-officer`**. These rules are blocking. `security-officer`
runs in parallel with `qa-reviewer` and `devops-engineer` on every PR.

## Code hot paths (HARD RULE)

| Risk | Forbidden | Required |
|---|---|---|
| SSRF | `httpx.get(f"https://{user_input}")` | Validate via `core.validators` first |
| SQL injection | f-string SQL, `text(f"SELECT … {x}")` | SQLAlchemy Core with bound params |
| Path traversal | `open(f"{dir}/{user_input}")` | `pathlib.Path` + `.resolve()` + boundary check |
| YAML | `yaml.load` | `yaml.safe_load` |
| Subprocess | `shell=True`, string command | `[argv]`, `shell=False`, `check=True`, `timeout=N` |
| Pickle | `pickle.loads` of external data | `json` / explicit schema |
| TLS | `verify=False`, `_create_unverified_context` | Default verification, pinned CA if needed |

## Secrets (HARD RULE)

- API keys load from env or `~/.config/domainraptor/config.yaml` only.
- **Never** log secrets. Use `utils.redact()` on any structure that
  *might* contain `Authorization`, `X-Api-Key`, cookies, tokens.
- `detect-secrets` baseline (`.secrets.baseline`) must stay current.
- CI secrets: GitHub Secrets + OIDC. No PAT in env. No `${{ secrets.X }}`
  printed via `echo`.

## Dependencies (HARD RULE)

- `uv pip audit` clean for `high`/`critical`. `medium` needs a comment
  in PR with remediation date. `low` documented in `SECURITY.md`.
- Pin transitive CVE-prone deps in `pyproject.toml` `[tool.uv.constraints]`
  when no upstream fix.

## Bandit (HARD RULE)

- `uv run bandit -r src/` → zero `medium`/`high`.
- `low` requires `# nosec B### -- reason` (specific code, real reason).
- No blanket `# nosec` ever.

## Logging safety (HARD RULE)

- Forbidden: `logger.info("response: %s", response.content)`.
- Forbidden: `logger.debug("headers: %s", dict(headers))`.
- Required: log only metadata (status, length, redacted host).

## IaC (when introduced)

- `checkov` + `trivy fs` mandatory in CI.
- Dockerfile: multi-stage, non-root user, base pinned by digest,
  `HEALTHCHECK` defined, `.dockerignore` present.
- Terraform: no inline secrets, state in encrypted backend, drift check
  in CI.
- Kubernetes: `securityContext` with `runAsNonRoot: true`,
  `readOnlyRootFilesystem: true`, no `:latest` images.

## Threat-modeling cadence

`security-officer plan` runs at sprint kickoff for:
- New external integrations (`discovery/*_client.py`, `enrichment/*`).
- Storage backend changes.
- Any task touching `core/config.py` or auth/secret loading.
- Any PR introducing `infra/`, `Dockerfile`, `*.tf`.

Output: `T###-sec-*.md` task in current sprint with STRIDE summary.

## Vulnerability disclosure

`SECURITY.md` at repo root describes reporting channel. `security-officer`
owns updates to it.
