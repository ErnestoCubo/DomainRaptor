"""Dashboard screen: overview + DB stats + recent scans."""

from __future__ import annotations

import contextlib

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
    DashboardScreen #dash-hint { color: $text-muted; padding-top: 1; }
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
            table = DataTable(id="recent-scans", cursor_type="row")
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
            yield Static(
                "Tip: select a row and press Enter to open it in Reports.",
                id="dash-hint",
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Open the selected scan's target in the Reports screen."""
        try:
            row = event.data_table.get_row(event.row_key)
        except Exception:
            return
        if len(row) < 2:
            return
        target = str(row[1])
        app = self.app
        # Switch to reports screen then prefill target input
        if hasattr(app, "action_switch"):
            app.action_switch("reports")
            # The new screen mounts asynchronously; defer the prefill.
            from textual.widgets import Input

            def _prefill() -> None:
                with contextlib.suppress(Exception):
                    target_input = app.query_one("#target", Input)
                    target_input.value = target

            app.call_after_refresh(_prefill)

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
