"""Compare screen."""

from __future__ import annotations

import contextlib

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Button, Input, Label, Select, Static

from domainraptor.tui.screens._common import ScanRunner


class CompareScreen(Widget):
    DEFAULT_CSS = """
    CompareScreen { height: 1fr; }
    CompareScreen .arg-row { height: auto; }
    CompareScreen .arg-row Label { padding: 1 1 0 0; width: 8; }
    CompareScreen .arg-row Input { width: 1fr; }
    CompareScreen #cmp-run { margin-top: 1; }
    """

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
            with Horizontal(classes="arg-row", id="row-arg1"):
                yield Label("Arg 1:")
                yield Input(placeholder="target or scan-id", id="arg1")
            with Horizontal(classes="arg-row", id="row-arg2"):
                yield Label("Arg 2:")
                yield Input(placeholder="(optional) scan-id or target", id="arg2")
            yield Button("Run", id="cmp-run", variant="primary")
            yield ScanRunner(id="runner")

    def on_mount(self) -> None:
        self._apply_subcmd_visibility("history")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "subcmd":
            self._apply_subcmd_visibility(str(event.value))

    def _apply_subcmd_visibility(self, sub: str) -> None:
        # 'history' takes no positional args, only target via the form. Hide arg rows.
        # 'scans' takes two scan-ids. 'targets' takes two targets.
        show_args = sub != "history"
        for row_id in ("row-arg1", "row-arg2"):
            with contextlib.suppress(Exception):
                self.query_one(f"#{row_id}").display = show_args

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id in {"arg1", "arg2"}:
            self.post_message(ScanRunner.RunRequested())
            event.stop()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cmp-run":
            self.post_message(ScanRunner.RunRequested())
            event.stop()

    def on_scan_runner_run_requested(self, _: ScanRunner.RunRequested) -> None:
        runner = self.query_one("#runner", ScanRunner)
        sub = str(self.query_one("#subcmd", Select).value)
        if sub == "history":
            runner.run_command(["compare", "history"])
            return
        a = self.query_one("#arg1", Input).value.strip()
        b = self.query_one("#arg2", Input).value.strip()
        if not a:
            runner.append("[yellow]Please provide at least Arg 1.[/yellow]")
            return
        args = ["compare", sub, a]
        if b:
            args.append(b)
        runner.run_command(args)
