"""Reports screen: generate and list reports."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Button, Input, Label, Select, Static

from domainraptor.tui.screens._common import ScanRunner


class ReportsScreen(Widget):
    DEFAULT_CSS = """
    ReportsScreen { height: 1fr; }
    ReportsScreen .field-row { height: auto; }
    ReportsScreen .field-row Label { padding: 1 1 0 0; }
    ReportsScreen .field-row Input { width: 1fr; }
    ReportsScreen .field-row Select { width: 1fr; }
    ReportsScreen #rp-run { margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Reports", classes="title")
            yield Static("Generate, list and export reports.", classes="subtitle")
            yield Label("Subcommand", classes="field-label")
            yield Select(
                [
                    ("generate", "generate"),
                    ("summary", "summary"),
                    ("list", "list"),
                    ("export", "export"),
                ],
                value="generate",
                id="subcmd",
                allow_blank=False,
            )
            with Horizontal(classes="field-row"):
                yield Label("Target:")
                yield Input(placeholder="example.com", id="target")
            with Horizontal(classes="field-row"):
                yield Label("Format:")
                yield Select(
                    [(f, f) for f in ("html", "json", "yaml", "md", "pdf", "csv")],
                    value="html",
                    id="fmt",
                    allow_blank=False,
                )
            with Horizontal(classes="field-row"):
                yield Label("Output file:")
                yield Input(placeholder="report.html", id="output")
            yield Button("Run", id="rp-run", variant="primary")
            yield ScanRunner(id="runner")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id in {"target", "output"}:
            self.post_message(ScanRunner.RunRequested())
            event.stop()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "rp-run":
            self.post_message(ScanRunner.RunRequested())
            event.stop()

    def on_scan_runner_run_requested(self, _: ScanRunner.RunRequested) -> None:
        runner = self.query_one("#runner", ScanRunner)
        sub = str(self.query_one("#subcmd", Select).value)
        target = self.query_one("#target", Input).value.strip()
        fmt = str(self.query_one("#fmt", Select).value)
        output = self.query_one("#output", Input).value.strip()
        if sub in {"generate", "summary", "export"} and not target:
            runner.append(f"[yellow]Target required for '{sub}'.[/yellow]")
            return
        args = ["report", sub]
        if target:
            args.append(target)
        if sub in {"generate", "export"}:
            args += ["--format", fmt]
            if output:
                args += ["--output", output]
        runner.run_command(args)
