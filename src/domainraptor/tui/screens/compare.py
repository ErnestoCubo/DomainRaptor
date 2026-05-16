"""Compare screen."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Input, Label, Select, Static

from domainraptor.tui.screens._common import ScanRunner


class CompareScreen(Widget):
    DEFAULT_CSS = """CompareScreen { height: 1fr; }"""

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Compare", classes="title")
            yield Static("Compare scans over time or between targets.", classes="subtitle")
            yield Label("Subcommand", classes="field-label")
            yield Select(
                [("history", "history"), ("scans", "scans"), ("targets", "targets")],
                value="history",
                id="subcmd",
                allow_blank=False,
            )
            with Horizontal():
                yield Label("Arg 1:")
                yield Input(placeholder="target or scan-id", id="arg1")
                yield Label("Arg 2:")
                yield Input(placeholder="(optional) scan-id or target", id="arg2")
            yield ScanRunner(id="runner")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id in {"arg1", "arg2"}:
            self.post_message(ScanRunner.RunRequested())
            event.stop()

    def on_scan_runner_run_requested(self, _: ScanRunner.RunRequested) -> None:
        runner = self.query_one("#runner", ScanRunner)
        sub = str(self.query_one("#subcmd", Select).value)
        a = self.query_one("#arg1", Input).value.strip()
        b = self.query_one("#arg2", Input).value.strip()
        if not a:
            runner.append("[yellow]Please provide at least Arg 1.[/yellow]")
            return
        args = ["compare", sub, a]
        if b:
            args.append(b)
        runner.run_command(args)
