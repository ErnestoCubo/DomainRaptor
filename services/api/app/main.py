"""FastAPI application entry point for the DomainRaptor HTTP API (REQ-001).

This module exposes the ASGI ``app`` instance. In Sprint 001 it intentionally
carries no business routes; subsequent tasks (T002-T016) mount settings, auth,
schemas, health probes, the OpenAPI contract, and the admin panel onto it.
"""

from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(
    title="DomainRaptor API",
    summary="HTTP control plane for DomainRaptor reconnaissance data.",
    version="0.1.0",
)


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    """Minimal liveness placeholder until health probes land in T007."""
    return {"service": "domainraptor-api", "status": "ok"}
