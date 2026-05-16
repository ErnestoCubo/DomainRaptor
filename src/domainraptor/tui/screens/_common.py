"""Shared widget building blocks for TUI screens."""

from __future__ import annotations

import contextlib
import random
import shlex

from textual import work
from textual.containers import Container, Horizontal, Vertical
from textual.message import Message
from textual.timer import Timer
from textual.widgets import Button, Input, Label, ProgressBar, RichLog, Static

# Fun rotating phrases shown while a scan runs. DomainRaptor lore + cyber refs.
LORE_PHRASES: list[str] = [
    "🦖 The raptor is stalking its prey...",
    "🔍 Sniffing DNS packets in the digital savanna...",
    "🌐 Crawling certificate transparency logs...",
    "🛰️  Bouncing queries off global resolvers...",
    "⚔️  Bypassing dragon-firewalls...",
    "📜 Reading ancient WHOIS scrolls...",
    "🦴 Digging through the bone-yard of subdomains...",
    "🦅 Soaring over port 443...",
    "🐍 Tasting the SSL handshake...",
    "🧬 Decoding the DNA of the target...",
    "💀 Awakening the kraken of misconfigurations...",
    "🔮 Consulting the oracle of Shodan...",
    "🗡️  Forking processes like Hydra heads...",
    "🪐 Reaching the edge of the IP space...",
    "📡 Triangulating ASN coordinates...",
    "🛡️  Probing the citadel's TLS gates...",
    "🕷️  Spinning recon webs across the net...",
    "⚡ Sending TCP SYN lightning bolts...",
    "🦠 Fingerprinting the host's strain...",
    "🎯 Locking onto the target domain...",
]


class ScanRunner(Vertical):
    """Self-contained subprocess runner with action bar + status + log."""

    DEFAULT_CSS = """
    ScanRunner { height: 1fr; }
    ScanRunner Horizontal#sr-actions { height: auto; padding-top: 1; }
    ScanRunner #sr-progress-row { height: auto; padding: 0 1; }
    ScanRunner #sr-progress-row ProgressBar { width: 1fr; }
    ScanRunner #sr-lore { color: $accent; padding: 0 1; height: 1; text-style: italic; }
    ScanRunner RichLog { height: 1fr; border: solid $primary; margin-top: 1; }
    ScanRunner #sr-status { color: $text-muted; padding: 0 1; }
    """

    class RunRequested(Message):
        """Emitted when the user presses the Run button."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._lore_timer: Timer | None = None
        self._progress_timer: Timer | None = None
        self._fake_progress: float = 0.0

    def compose(self):
        with Horizontal(id="sr-actions"):
            yield Button("Run", id="sr-run", variant="primary")
            yield Button("Stop", id="sr-stop", variant="error")
            yield Button("Clear", id="sr-clear")
        yield Static("Idle", id="sr-status")
        with Horizontal(id="sr-progress-row"):
            yield ProgressBar(total=100, id="sr-progress", show_eta=False)
        yield Static("", id="sr-lore")
        yield RichLog(id="sr-log", highlight=True, markup=True, wrap=True)

    def append(self, line: str) -> None:
        self.query_one("#sr-log", RichLog).write(line.rstrip())

    def set_status(self, text: str) -> None:
        self.query_one("#sr-status", Static).update(text)

    def _set_lore(self, text: str) -> None:
        self.query_one("#sr-lore", Static).update(text)

    def _rotate_lore(self) -> None:
        self._set_lore(random.choice(LORE_PHRASES))

    def _tick_progress(self) -> None:
        # Asymptotic fake progress: never reach 100 until command completes.
        self._fake_progress += (95 - self._fake_progress) * 0.05
        with contextlib.suppress(Exception):
            self.query_one("#sr-progress", ProgressBar).update(progress=self._fake_progress)

    def _start_loading_ui(self) -> None:
        self._fake_progress = 0.0
        with contextlib.suppress(Exception):
            self.query_one("#sr-progress", ProgressBar).update(total=100, progress=0)
        self._rotate_lore()
        if self._lore_timer is None:
            self._lore_timer = self.set_interval(3.0, self._rotate_lore)
        if self._progress_timer is None:
            self._progress_timer = self.set_interval(0.4, self._tick_progress)

    def _stop_loading_ui(self, *, success: bool) -> None:
        if self._lore_timer is not None:
            self._lore_timer.stop()
            self._lore_timer = None
        if self._progress_timer is not None:
            self._progress_timer.stop()
            self._progress_timer = None
        with contextlib.suppress(Exception):
            self.query_one("#sr-progress", ProgressBar).update(progress=100 if success else 0)
        self._set_lore("[green]Done.[/green]" if success else "[yellow]Stopped.[/yellow]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "sr-clear":
            self.query_one("#sr-log", RichLog).clear()
            self.set_status("Idle")
            self._set_lore("")
            with contextlib.suppress(Exception):
                self.query_one("#sr-progress", ProgressBar).update(progress=0)
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
        self._stop_loading_ui(success=False)
        self.set_status("Cancelled")

    @work(thread=True, exclusive=True)
    def run_command(self, args: list[str]) -> None:
        import os
        import subprocess
        import sys

        cmdline = "domainraptor " + shlex.join(args)
        self.app.call_from_thread(self.set_status, f"Running: {cmdline}")
        self.app.call_from_thread(self.append, f"[bold cyan]$ {cmdline}[/]")
        self.app.call_from_thread(self._start_loading_ui)

        # Force unbuffered child output so we can stream lines live.
        env = {**os.environ, "PYTHONUNBUFFERED": "1", "FORCE_COLOR": "1"}

        try:
            proc = subprocess.Popen(
                [sys.executable, "-m", "domainraptor.cli.main", "--no-banner", *args],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
            )
        except (FileNotFoundError, OSError) as exc:
            self.app.call_from_thread(
                self.append, f"[red]Failed to launch domainraptor: {exc}[/red]"
            )
            self.app.call_from_thread(self._stop_loading_ui, success=False)
            self.app.call_from_thread(self.set_status, "Error")
            return

        assert proc.stdout is not None
        for line in proc.stdout:
            self.app.call_from_thread(self.append, line)
        rc = proc.wait()
        success = rc == 0
        self.app.call_from_thread(self._stop_loading_ui, success=success)
        msg = "Finished" if success else f"[red]Failed (exit {rc})[/red]"
        self.app.call_from_thread(self.set_status, msg)


class TargetForm(Container):
    """A labeled target Input with an inline Run button."""

    DEFAULT_CSS = """
    TargetForm { height: auto; padding: 1 0; }
    TargetForm Label { padding: 1 1 0 0; }
    TargetForm Input { width: 1fr; }
    TargetForm Button#tf-run { margin-left: 1; }
    """

    def __init__(self, placeholder: str = "example.com", input_id: str = "target") -> None:
        super().__init__()
        self._placeholder = placeholder
        self._input_id = input_id

    def compose(self):
        with Horizontal():
            yield Label("Target:")
            yield Input(placeholder=self._placeholder, id=self._input_id)
            yield Button("Run", id="tf-run", variant="primary")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # Pressing Enter in the target input triggers the same flow as Run.
        if event.input.id == self._input_id:
            self.post_message(ScanRunner.RunRequested())
            event.stop()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "tf-run":
            self.post_message(ScanRunner.RunRequested())
            event.stop()

    @property
    def target(self) -> str:
        return self.query_one(f"#{self._input_id}", Input).value.strip()
