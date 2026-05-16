"""Shared widget building blocks for TUI screens."""

from __future__ import annotations

import shlex

from textual import work
from textual.containers import Container, Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, Input, Label, RichLog, Static


class ScanRunner(Vertical):
    """Self-contained subprocess runner with action bar + status + log."""

    DEFAULT_CSS = """
    ScanRunner { height: 1fr; }
    ScanRunner Horizontal#sr-actions { height: auto; padding-top: 1; }
    ScanRunner RichLog { height: 1fr; border: solid $primary; margin-top: 1; }
    ScanRunner #sr-status { color: $text-muted; padding: 0 1; }
    """

    class RunRequested(Message):
        """Emitted when the user presses the Run button."""

    def compose(self):
        with Horizontal(id="sr-actions"):
            yield Button("Run", id="sr-run", variant="primary")
            yield Button("Stop", id="sr-stop", variant="error")
            yield Button("Clear", id="sr-clear")
        yield Static("Idle", id="sr-status")
        yield RichLog(id="sr-log", highlight=True, markup=True, wrap=True)

    def append(self, line: str) -> None:
        self.query_one("#sr-log", RichLog).write(line.rstrip())

    def set_status(self, text: str) -> None:
        self.query_one("#sr-status", Static).update(text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "sr-clear":
            self.query_one("#sr-log", RichLog).clear()
            self.set_status("Idle")
            event.stop()
        elif event.button.id == "sr-stop":
            self.cancel_running()
            event.stop()
        elif event.button.id == "sr-run":
            self.post_message(self.RunRequested())
            event.stop()

    def cancel_running(self) -> None:
        for worker in list(self.workers):
            worker.cancel()
        self.set_status("Cancelled")

    @work(thread=True, exclusive=True)
    def run_command(self, args: list[str]) -> None:
        import subprocess
        import sys

        cmdline = "domainraptor " + shlex.join(args)
        self.app.call_from_thread(self.set_status, f"Running: {cmdline}")
        self.app.call_from_thread(self.append, f"[bold cyan]$ {cmdline}[/]")

        try:
            proc = subprocess.Popen(
                [sys.executable, "-m", "domainraptor.cli.main", "--no-banner", *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except (FileNotFoundError, OSError) as exc:
            self.app.call_from_thread(
                self.append, f"[red]Failed to launch domainraptor: {exc}[/red]"
            )
            self.app.call_from_thread(self.set_status, "Error")
            return

        assert proc.stdout is not None
        for line in proc.stdout:
            self.app.call_from_thread(self.append, line)
        rc = proc.wait()
        msg = "Finished" if rc == 0 else f"[red]Failed (exit {rc})[/red]"
        self.app.call_from_thread(self.set_status, msg)


class TargetForm(Container):
    """A labeled target Input."""

    DEFAULT_CSS = """
    TargetForm { height: auto; padding: 1 0; }
    TargetForm Label { padding-right: 1; }
    """

    def __init__(self, placeholder: str = "example.com", input_id: str = "target") -> None:
        super().__init__()
        self._placeholder = placeholder
        self._input_id = input_id

    def compose(self):
        with Horizontal():
            yield Label("Target:")
            yield Input(placeholder=self._placeholder, id=self._input_id)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # Pressing Enter in the target input triggers the same flow as Run.
        if event.input.id == self._input_id:
            self.post_message(ScanRunner.RunRequested())
            event.stop()

    @property
    def target(self) -> str:
        return self.query_one(f"#{self._input_id}", Input).value.strip()
