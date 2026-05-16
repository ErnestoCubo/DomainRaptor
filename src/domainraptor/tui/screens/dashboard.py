"""Dashboard screen: overview + DB stats + recent scans."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import DataTable, Label, Static

from domainraptor import __version__
from domainraptor.storage.database import get_database
from domainraptor.storage.repository import ScanRepository


class _StatCard(Container):
    DEFAULT_CSS = """
    _StatCard { border: solid $accent; padding: 1 2; height: 5; content-align: center middle; }
    .stat-value { color: $accent; text-style: bold; }
    """

    def __init__(self, title: str, value: str) -> None:
        super().__init__()
        self._title = title
        self._value = value

    def compose(self) -> ComposeResult:
        yield Label(self._title)
        yield Label(self._value, classes="stat-value")


class DashboardScreen(Widget):
    DEFAULT_CSS = """
    DashboardScreen .grid { layout: grid; grid-size: 4 1; grid-gutter: 1 2; height: auto; margin-bottom: 1; }
    DashboardScreen DataTable { height: 20; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(f"DomainRaptor v{__version__} - Dashboard", classes="title")
            yield Static(
                "Overview of your database, recent scans and active watches.",
                classes="subtitle",
            )

            stats = self._safe_stats()
            with Horizontal(classes="grid"):
                yield _StatCard("Scans", str(stats.get("scans", 0)))
                yield _StatCard("Assets", str(stats.get("assets", 0)))
                yield _StatCard("Vulnerabilities", str(stats.get("vulnerabilities", 0)))
                yield _StatCard("Watches", str(stats.get("watch_targets", 0)))

            yield Label("Recent scans", classes="field-label")
            table = DataTable(id="recent-scans")
            table.add_columns("ID", "Target", "Type", "Status", "Started")
            for scan in self._recent_scans():
                # list_scans returns summary dicts
                started = scan.get("started_at") or ""
                table.add_row(
                    str(scan.get("id", "?")),
                    str(scan.get("target", "?")),
                    str(scan.get("scan_type", "-")),
                    str(scan.get("status", "-")),
                    str(started)[:19] if started else "-",
                )
            yield table

    @staticmethod
    def _safe_stats() -> dict:
        try:
            return get_database().get_stats()
        except Exception as exc:  # pragma: no cover - defensive
            return {"error": str(exc)}

    @staticmethod
    def _recent_scans() -> list:
        try:
            return ScanRepository(get_database()).list_scans(limit=20)
        except Exception:  # pragma: no cover - defensive
            return []
