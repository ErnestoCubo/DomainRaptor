"""Safe JSON (de)serialization helpers with logging.

Used by the storage layer to avoid scattering ``json.dumps``/``json.loads``
boilerplate and silent ``or "{}"`` / ``or "[]"`` patterns.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


def json_dumps(obj: Any) -> str:
    """Serialize ``obj`` to a JSON string.

    Falls back to ``"{}"`` and logs if serialization fails (e.g. an object
    that is not JSON-serialisable slipped through). ``default=str`` lets us
    cope with ``datetime`` and similar types without crashing the DB write.
    """
    try:
        return json.dumps(obj, default=str)
    except (TypeError, ValueError) as exc:
        logger.error("JSON serialization failed (%r): %s", type(obj).__name__, exc)
        return "{}"


def json_loads_dict(s: str | None, default: dict | None = None) -> dict:
    """Parse ``s`` as a JSON object, returning ``default`` (or ``{}``) on error."""
    fallback: dict = default if default is not None else {}
    if not s:
        return fallback
    try:
        value = json.loads(s)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("JSON parse failed (expected dict): %s", exc)
        return fallback
    if not isinstance(value, dict):
        logger.warning("JSON value is %s, expected dict", type(value).__name__)
        return fallback
    return value


def json_loads_list(s: str | None, default: list | None = None) -> list:
    """Parse ``s`` as a JSON array, returning ``default`` (or ``[]``) on error."""
    fallback: list = default if default is not None else []
    if not s:
        return fallback
    try:
        value = json.loads(s)
    except (json.JSONDecodeError, ValueError) as exc:
        logger.warning("JSON parse failed (expected list): %s", exc)
        return fallback
    if not isinstance(value, list):
        logger.warning("JSON value is %s, expected list", type(value).__name__)
        return fallback
    return value


__all__ = ["json_dumps", "json_loads_dict", "json_loads_list"]
