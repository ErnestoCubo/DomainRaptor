"""Watch screen: manage watch targets."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Button, DataTable, Input, Label, Select, Static

from domainraptor.storage.database import get_database
from domainraptor.storage.repository import WatchRepository
from domainraptor.tui.screens._common import ScanRunner


class WatchScreen(Widget):
    DEFAULT_CSS = """
    WatchScreen { height: 1fr; }
    WatchScreen .field-row { height: auto; }
    WatchScreen .field-row Label { padding: 1 1 0 0; }
    WatchScreen .field-row Input { width: 1fr; }
    WatchScreen #w-run { margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Watch", classes="title")
            yield Static("Manage continuous monitoring targets.", classes="subtitle")
            yield Label("Action", classes="field-label")
            yield Select(
                [
                    ("add", "add"),
                    ("remove", "remove"),
                    ("list", "list"),
                    ("run", "run"),
                    ("pause", "pause"),
                    ("resume", "resume"),
                    ("status", "status"),
                ],
                value="list",
                id="action",
                allow_blank=False,
            )
            with Horizontal(classes="field-row"):
                yield Label("Target:")
                yield Input(placeholder="example.com", id="target")
            with Horizontal(classes="field-row"):
                yield Label("Interval (add):")
                yield Input(placeholder="24h", id="interval", value="24h")
            with Horizontal():
                yield Button("Run", id="w-run", variant="primary")
                yield Button("Refresh DB view", id="refresh")
            yield DataTable(id="watch-table")
            yield ScanRunner(id="runner")

    def on_mount(self) -> None:
        table = self.query_one("#watch-table", DataTable)
        table.add_columns("ID", "Target", "Type", "Interval", "Enabled", "Last check")
        self._refresh_table()

    def _refresh_table(self) -> None:
        table = self.query_one("#watch-table", DataTable)
        table.clear()
        try:
            for w in WatchRepository(get_database()).list_all():
                table.add_row(
                    str(getattr(w, "id", "?")),
                    getattr(w, "target", "?"),
                    getattr(w, "watch_type", "-"),
                    str(getattr(w, "interval", "-")),
                    str(getattr(w, "enabled", "-")),
                    str(getattr(w, "last_checked_at", "-") or "-")[:19],
                )
        except Exception as exc:  # pragma: no cover - defensive
            self.query_one("#runner", ScanRunner).append(f"[red]DB error: {exc}[/red]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "refresh":
            self._refresh_table()
        elif event.button.id == "w-run":
            self.post_message(ScanRunner.RunRequested())
            event.stop()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # Pressing Enter in any input triggers the same flow as Run.
        if event.input.id in {"target", "interval"}:
            self.post_message(ScanRunner.RunRequested())
            event.stop()

    def on_scan_runner_run_requested(self, _: ScanRunner.RunRequested) -> None:
        runner = self.query_one("#runner", ScanRunner)
        action = str(self.query_one("#action", Select).value)
        target = self.query_one("#target", Input).value.strip()
        args = ["watch", action]
        if action in {"add", "remove", "pause", "resume", "status"} and not target:
            runner.append(f"[yellow]Target required for action '{action}'.[/yellow]")
            return
        if action == "add":
            interval = self.query_one("#interval", Input).value.strip() or "24h"
            args += [target, "--interval", interval]
        elif action in {"remove", "pause", "resume", "status"}:
            args += [target, *(["--force"] if action == "remove" else [])]
        elif action == "run" and target:
            args.append(target)
        runner.run_command(args)
        self._refresh_table()
