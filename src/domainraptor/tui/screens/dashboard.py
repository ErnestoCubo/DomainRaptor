"""Dashboard screen: overview + DB stats + recent scans."""

from __future__ import annotations

import contextlib
from collections import Counter
from datetime import datetime, timedelta

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import DataTable, Label, Sparkline, Static

from domainraptor import __version__
from domainraptor.storage.database import get_database
from domainraptor.storage.repository import ScanRepository


class _StatCard(Container):
    """A clickable stat card. Clicking switches to the linked screen."""

    DEFAULT_CSS = """
    _StatCard { border: solid $accent; padding: 1 2; height: 5; content-align: center middle; }
    _StatCard:hover { border: solid $primary; background: $boost; }
    .stat-value { color: $accent; text-style: bold; }
    """

    def __init__(self, title: str, value: str, target_screen: str | None = None) -> None:
        super().__init__()
        self._title = title
        self._value = value
        self._target_screen = target_screen

    def compose(self) -> ComposeResult:
        yield Label(self._title)
        yield Label(self._value, classes="stat-value")

    def on_click(self) -> None:
        if not self._target_screen:
            return
        app = self.app
        if hasattr(app, "action_switch"):
            app.action_switch(self._target_screen)


class DashboardScreen(Widget):
    DEFAULT_CSS = """
    DashboardScreen .grid { layout: grid; grid-size: 4 1; grid-gutter: 1 2; height: auto; margin-bottom: 1; }
    DashboardScreen DataTable { height: 14; }
    DashboardScreen #dash-hint { color: $text-muted; padding-top: 1; }
    DashboardScreen #spark-box { border: solid $accent; padding: 0 1; height: 5; margin-top: 1; margin-bottom: 1; }
    DashboardScreen Sparkline { height: 3; }
    DashboardScreen Sparkline > .sparkline--max-color { color: $accent; }
    DashboardScreen Sparkline > .sparkline--min-color { color: $primary; }
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
                yield _StatCard("Scans", str(stats.get("scans", 0)), target_screen="discover")
                yield _StatCard("Assets", str(stats.get("assets", 0)), target_screen="database")
                yield _StatCard(
                    "Vulnerabilities",
                    str(stats.get("vulnerabilities", 0)),
                    target_screen="assess",
                )
                yield _StatCard(
                    "Watches", str(stats.get("watch_targets", 0)), target_screen="watch"
                )

            # 14-day scan activity sparkline
            with Vertical(id="spark-box"):
                yield Label("Scan activity (last 14 days)", classes="field-label")
                yield Sparkline(self._scan_activity(days=14), id="scan-spark")

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
                "Tip: click a stat card to jump to its screen, or select a scan row "
                "and press Enter to open it in Reports.",
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

    @staticmethod
    def _scan_activity(days: int = 14) -> list[int]:
        """Return a list of scan counts for the last `days` days (oldest first)."""
        try:
            scans = ScanRepository(get_database()).list_scans(limit=500)
        except Exception:  # pragma: no cover - defensive
            return [0] * days

        today = datetime.now().date()
        counter: Counter[str] = Counter()
        for scan in scans:
            started = scan.get("started_at")
            if not started:
                continue
            day = str(started)[:10]
            counter[day] += 1
        series: list[int] = []
        for i in range(days - 1, -1, -1):
            day = (today - timedelta(days=i)).isoformat()
            series.append(counter.get(day, 0))
        return series
