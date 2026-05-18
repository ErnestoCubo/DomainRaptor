"""Assess screen: vulnerability and configuration assessment."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widget import Widget
from textual.widgets import Checkbox, Label, Select, Static

from domainraptor.tui.screens._common import ScanRunner, TargetForm


class AssessScreen(Widget):
    DEFAULT_CSS = """AssessScreen { height: 1fr; }"""

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label("Assess", classes="title")
            yield Static(
                "Assess vulnerabilities, configuration and outdated software.", classes="subtitle"
            )
            yield TargetForm(placeholder="example.com")
            yield Label("Subcommand", classes="field-label")
            yield Select(
                [("vulns", "vulns"), ("config", "config"), ("outdated", "outdated")],
                value="vulns",
                id="subcmd",
                allow_blank=False,
            )
            yield Label("Min severity (vulns only)", classes="field-label")
            yield Select(
                [(s, s) for s in ("info", "low", "medium", "high", "critical")],
                value="low",
                id="severity",
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
        subcmd = str(self.query_one("#subcmd", Select).value)
        args: list[str] = []
        if self.query_one("#free-only", Checkbox).value:
            args.append("--free-only")
        if self.query_one("#verbose", Checkbox).value:
            args.append("--verbose")
        args += ["assess", subcmd, target]
        if subcmd == "vulns":
            args += ["--min-severity", str(self.query_one("#severity", Select).value)]
        runner.run_command(args)
