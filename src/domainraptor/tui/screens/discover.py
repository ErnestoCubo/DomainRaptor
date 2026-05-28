"""Discover screen."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, VerticalScroll
from textual.widget import Widget
from textual.widgets import Checkbox, Label, Select, Static

from domainraptor.tui.screens._common import ScanRunner, TargetForm


class DiscoverScreen(Widget):
    DEFAULT_CSS = """DiscoverScreen { height: 1fr; }"""

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Label("Discover", classes="title")
            yield Static(
                "Discover subdomains, DNS records, certificates, ports and WHOIS info.",
                classes="subtitle",
            )
            yield TargetForm(placeholder="example.com")
            yield Label("Subcommand", classes="field-label")
            yield Select(
                [
                    ("subdomains", "subdomains"),
                    ("dns", "dns"),
                    ("certs", "certs"),
                    ("ports", "ports"),
                    ("whois", "whois"),
                    ("wayback", "wayback"),
                    ("asn", "asn"),
                ],
                value="subdomains",
                id="subcmd",
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
        args += ["discover", subcmd, target]
        runner.run_command(args)
