"""Reports screen: generate, list and preview reports."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Button, Input, Label, RichLog, Select, Static

from domainraptor.tui.screens._common import ScanRunner
from domainraptor.tui.screens._preview import render_preview


class ReportsScreen(Widget):
    DEFAULT_CSS = """
    ReportsScreen { height: 1fr; }
    ReportsScreen .field-row { height: auto; }
    ReportsScreen .field-row Label { padding: 1 1 0 0; }
    ReportsScreen .field-row Input { width: 1fr; }
    ReportsScreen .field-row Select { width: 1fr; }
    ReportsScreen #rp-run-row { height: auto; padding-top: 1; }
    ReportsScreen #rp-preview { height: 22; border: solid $accent; margin-top: 1; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Reports", classes="title")
            yield Static("Generate, list, export and preview reports.", classes="subtitle")
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
            with Horizontal(id="rp-run-row"):
                yield Button("Run", id="rp-run", variant="primary")
                yield Button("Preview output", id="rp-preview-btn")
            yield Label("Preview", classes="field-label")
            yield RichLog(id="rp-preview", highlight=False, markup=False, wrap=True)
            yield ScanRunner(id="runner")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id in {"target", "output"}:
            self.post_message(ScanRunner.RunRequested())
            event.stop()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "rp-run":
            self.post_message(ScanRunner.RunRequested())
            event.stop()
        elif event.button.id == "rp-preview-btn":
            self._preview_output()
            event.stop()

    def _preview_output(self) -> None:
        preview = self.query_one("#rp-preview", RichLog)
        preview.clear()
        path_str = self.query_one("#output", Input).value.strip()
        if not path_str:
            preview.write("[no output path set]")
            return
        path = Path(path_str).expanduser()
        if not path.exists():
            preview.write(f"[file not found: {path}]")
            return
        if path.stat().st_size > 2 * 1024 * 1024:
            preview.write(f"[file too large to preview: {path.stat().st_size} bytes]")
            return
        try:
            renderable = render_preview(path)
        except Exception as exc:  # pragma: no cover - defensive
            preview.write(f"[preview error: {exc}]")
            return
        preview.write(renderable)

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
