"""Shared helpers for Typer command callbacks.

Avoid duplicating ``ctx.obj.get("config", AppConfig())`` in every command —
that pattern is mirror-imaged across ~12 callbacks and any subtle change
(default config, error reporting) needs to land everywhere.
"""

from __future__ import annotations

import typer

from domainraptor.core.config import AppConfig


def get_app_config(ctx: typer.Context) -> AppConfig:
    """Return the `AppConfig` stored on the Typer context, or a fresh default.

    Mirrors the historical inline pattern
    ``ctx.obj.get("config", AppConfig())`` so call sites can be migrated
    one-for-one without behavioural change.
    """
    if ctx.obj is None:
        return AppConfig()
    return ctx.obj.get("config", AppConfig())
