# DomainRaptor Security Policy

## Reporting a vulnerability

Please report security issues privately. Do **not** open a public issue.

- Open a private security advisory:
  <https://github.com/ErnestoCubo/DomainRaptor/security/advisories/new>
- Or email the maintainer (see `pyproject.toml` for the project URL and
  follow the repository's contact channels).

Provide:

- Affected version (`dr --version`).
- Steps to reproduce.
- Impact assessment.
- Suggested mitigation if known.

We aim to acknowledge within 72 hours and to publish a fix or
mitigation within 30 days for high-severity issues.

## Supported versions

Security fixes target the latest `develop` and the latest released
version on PyPI. Older versions are best-effort.

## Hardening defaults

- TLS verification is always on for outbound HTTP. There is no flag to
  disable it.
- API keys load from env or `~/.config/domainraptor/config.yaml` only.
- Secrets are never logged (Authorization headers, API keys, cookies,
  full HTTP bodies are redacted).
- Subprocess invocations use `shell=False` with an explicit argv.
- YAML configs are parsed with `yaml.safe_load`.

## Dependency policy

We run `uv pip audit` on every PR. `high`/`critical` CVEs block merge
unless an explicit remediation plan with a date is recorded in the PR
and tracked here.

## Known advisories

(None at this time.)
