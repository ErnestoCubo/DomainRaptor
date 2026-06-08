"""Architecture boundary tests for the services/api package (REQ-001).

These tests enforce the narrow import contract between the isolated FastAPI
application (``services/api``) and the core library (``src/domainraptor``):

* ``services/api`` may import *only* a small allow-list of ``domainraptor``
  modules.
* ``src/domainraptor`` must never import the API application package.

The checks are AST-based so they fail the build on any disallowed import,
including one injected purely to verify the guard.
"""

from __future__ import annotations

import ast
from pathlib import Path

from app.main import app
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[3]
API_APP_DIR = REPO_ROOT / "services" / "api" / "app"
DOMAINRAPTOR_DIR = REPO_ROOT / "src" / "domainraptor"

# services/api may import ONLY these modules from src/domainraptor.
ALLOWED_DOMAINRAPTOR_IMPORTS = frozenset(
    {
        "domainraptor.storage._engine",
        "domainraptor.core.types",
        "domainraptor.core.exceptions",
    }
)


def _imported_modules(path: Path) -> set[str]:
    """Return the fully-qualified module names imported by a Python file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            modules.add(node.module)
    return modules


def _python_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.py"))


def test_api_imports_only_allowed_domainraptor_modules() -> None:
    violations: dict[str, set[str]] = {}
    for path in _python_files(API_APP_DIR):
        offending = {
            module
            for module in _imported_modules(path)
            if (module == "domainraptor" or module.startswith("domainraptor."))
            and module not in ALLOWED_DOMAINRAPTOR_IMPORTS
        }
        if offending:
            violations[str(path.relative_to(REPO_ROOT))] = offending
    assert not violations, f"Disallowed src/domainraptor imports in services/api: {violations}"


def test_domainraptor_never_imports_the_api_package() -> None:
    violations: dict[str, set[str]] = {}
    for path in _python_files(DOMAINRAPTOR_DIR):
        offending = {
            module
            for module in _imported_modules(path)
            if module == "app" or module.startswith("app.")
        }
        if offending:
            violations[str(path.relative_to(REPO_ROOT))] = offending
    assert not violations, f"src/domainraptor must not import services/api: {violations}"


def test_app_boots_and_serves_openapi() -> None:
    with TestClient(app) as client:
        response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.json()["info"]["title"] == "DomainRaptor API"
