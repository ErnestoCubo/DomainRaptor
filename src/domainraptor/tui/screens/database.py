"""Database screen: view DB stats and perform maintenance."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Button, DataTable, Label, Static

from domainraptor.storage.database import get_database


class DatabaseScreen(Widget):
    DEFAULT_CSS = """
    DatabaseScreen { height: 1fr; }
    DatabaseScreen DataTable { height: 18; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Database", classes="title")
            yield Static("View database statistics and run maintenance.", classes="subtitle")
            with Horizontal():
                yield Button("Refresh", id="refresh", variant="primary")
                yield Button("Vacuum", id="vacuum")
            yield Static("", id="db-status")
            yield DataTable(id="stats-table")

    def on_mount(self) -> None:
        table = self.query_one("#stats-table", DataTable)
        table.add_columns("Table", "Count")
        self._refresh()

    def _refresh(self) -> None:
        table = self.query_one("#stats-table", DataTable)
        table.clear()
        status = self.query_one("#db-status", Static)
        try:
            stats = get_database().get_stats()
        except Exception as exc:  # pragma: no cover - defensive
            status.update(f"[red]Error reading DB: {exc}[/red]")
            return
        size = stats.pop("file_size_bytes", 0)
        for k, v in stats.items():
            table.add_row(k, str(v))
        status.update(f"DB size: {size / 1024:.1f} KiB")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "refresh":
            self._refresh()
        elif event.button.id == "vacuum":
            status = self.query_one("#db-status", Static)
            try:
                get_database().vacuum()
                status.update("[green]Vacuum completed.[/green]")
                self._refresh()
            except Exception as exc:  # pragma: no cover - defensive
                status.update(f"[red]Vacuum failed: {exc}[/red]")
