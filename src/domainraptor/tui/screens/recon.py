"""Recon screen: run the full reconnaissance workflow."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Checkbox, Label, Select, Static

from domainraptor.tui.screens._common import ScanRunner, TargetForm


class ReconScreen(Widget):
    DEFAULT_CSS = """ReconScreen { height: 1fr; }"""

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Recon", classes="title")
            yield Static("Full reconnaissance workflow (discover + enrich).", classes="subtitle")
            yield TargetForm(placeholder="example.com")
            yield Label("Mode", classes="field-label")
            yield Select(
                [(m, m) for m in ("quick", "standard", "deep", "stealth")],
                value="standard",
                id="mode",
                allow_blank=False,
            )
            with Horizontal():
                yield Checkbox("Free only", id="free-only")
                yield Checkbox("Verbose", id="verbose")
            yield ScanRunner(id="runner")

    def on_scan_runner_run_requested(self, _: ScanRunner.RunRequested) -> None:
        runner = self.query_one("#runner", ScanRunner)
        target = self.query_one(TargetForm).target
        if not target:
            runner.append("[yellow]Please enter a target.[/yellow]")
            return
        mode = str(self.query_one("#mode", Select).value)
        args: list[str] = ["--mode", mode]
        if self.query_one("#free-only", Checkbox).value:
            args.append("--free-only")
        if self.query_one("#verbose", Checkbox).value:
            args.append("--verbose")
        args += ["recon", target]
        runner.run_command(args)
