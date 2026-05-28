"""Compare screen."""

from __future__ import annotations

import contextlib

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Input, Label, Select, Static

from domainraptor.tui.screens._common import ScanRunner


class CompareScreen(Widget):
    DEFAULT_CSS = """
    CompareScreen { height: 1fr; }
    CompareScreen .arg-row { height: auto; }
    CompareScreen .arg-row Label { padding: 1 1 0 0; width: 8; }
    CompareScreen .arg-row Input { width: 1fr; }
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
                yield Label("Target:", id="arg1-label")
                yield Input(placeholder="example.com", id="arg1")
            with Horizontal(classes="arg-row", id="row-arg2"):
                yield Label("Arg 2:")
                yield Input(placeholder="(optional) scan-id or target", id="arg2")
            # Run button is provided by ScanRunner; no separate one here.
            yield ScanRunner(id="runner")

    def on_mount(self) -> None:
        self._apply_subcmd_visibility("history")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "subcmd":
            self._apply_subcmd_visibility(str(event.value))

    def _apply_subcmd_visibility(self, sub: str) -> None:
        # All subcommands need a target/scan-id, so 'arg1' is always visible.
        # 'history' takes exactly one positional (target) — hide arg2.
        # 'scans' takes two scan-ids; 'targets' takes two targets — show arg2.
        arg1_label = "Target:" if sub in {"history", "targets"} else "Scan-id:"
        arg1_placeholder = "example.com" if sub in {"history", "targets"} else "scan-id (e.g. 42)"
        with contextlib.suppress(Exception):
            self.query_one("#arg1-label", Label).update(arg1_label)
            self.query_one("#arg1", Input).placeholder = arg1_placeholder
        with contextlib.suppress(Exception):
            self.query_one("#row-arg2").display = sub != "history"

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
            label = "target" if sub in {"history", "targets"} else "scan-id"
            runner.append(f"[yellow]Please provide a {label} in Arg 1.[/yellow]")
            return
        args = ["compare", sub, a]
        if b and sub != "history":
            args.append(b)
        runner.run_command(args)
