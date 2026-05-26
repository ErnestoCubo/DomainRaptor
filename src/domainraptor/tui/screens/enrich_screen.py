"""Enrich screen: third-party intelligence sources (URLScan, ...)."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widget import Widget
from textual.widgets import Checkbox, Input, Label, Select, Static

from domainraptor.tui.screens._common import ScanRunner, TargetForm


class EnrichScreen(Widget):
    DEFAULT_CSS = """EnrichScreen { height: 1fr; }"""

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label("Enrich", classes="title")
            yield Static(
                "Enrich a target with third-party intelligence sources.",
                classes="subtitle",
            )
            yield TargetForm(placeholder="example.com")
            yield Label("Source", classes="field-label")
            yield Select(
                [("urlscan", "urlscan"), ("all", "all")],
                value="urlscan",
                id="subcmd",
                allow_blank=False,
            )
            yield Label("Result limit (urlscan only)", classes="field-label")
            yield Input(value="25", id="limit")
            with Horizontal():
                yield Checkbox("Verbose", id="verbose")
            yield ScanRunner(id="runner")

    def on_scan_runner_run_requested(self, _: ScanRunner.RunRequested) -> None:
        runner = self.query_one("#runner", ScanRunner)
        target = self.query_one(TargetForm).target
        if not target:
            runner.append("[yellow]Please enter a target.[/yellow]")
            return
        subcmd = str(self.query_one("#subcmd", Select).value)
        args: list[str] = []
        if self.query_one("#verbose", Checkbox).value:
            args.append("--verbose")
        args += ["enrich", subcmd, target]
        if subcmd == "urlscan":
            limit = self.query_one("#limit", Input).value.strip()
            if limit:
                args += ["--limit", limit]
        runner.run_command(args)
