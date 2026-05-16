"""Config screen: view/edit API keys stored in ~/.domainraptor/.env."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Button, Input, Label, Static

ENV_FILE = Path.home() / ".domainraptor" / ".env"
KNOWN_KEYS = [
    "SHODAN_API_KEY",
    "NVD_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "CENSYS_API_ID",
    "CENSYS_API_SECRET",
]


class ConfigScreen(Widget):
    DEFAULT_CSS = """
    ConfigScreen { height: 1fr; }
    ConfigScreen Horizontal.row { height: auto; margin-bottom: 1; }
    ConfigScreen Label.key { width: 28; }
    """

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label("Config", classes="title")
            yield Static(
                f"API keys stored at: {ENV_FILE}\n"
                "Values are loaded into the environment on TUI startup.",
                classes="subtitle",
            )
            current = self._read_env()
            for key in KNOWN_KEYS:
                with Horizontal(classes="row"):
                    yield Label(key, classes="key")
                    yield Input(
                        value=current.get(key, ""),
                        placeholder="(unset)",
                        password=True,
                        id=f"key-{key}",
                    )
            with Horizontal():
                yield Button("Save", id="save", variant="primary")
                yield Button("Reload", id="reload")
            yield Static("", id="cfg-status")

    @staticmethod
    def _read_env() -> dict[str, str]:
        result: dict[str, str] = {}
        if not ENV_FILE.exists():
            return result
        for raw in ENV_FILE.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip().strip('"').strip("'")
        return result

    def _write_env(self, values: dict[str, str]) -> None:
        ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
        lines = [f'{k}="{v}"' for k, v in values.items() if v]
        ENV_FILE.write_text("\n".join(lines) + "\n")
        with contextlib.suppress(OSError):
            ENV_FILE.chmod(0o600)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        status = self.query_one("#cfg-status", Static)
        if event.button.id == "save":
            values: dict[str, str] = {}
            for key in KNOWN_KEYS:
                values[key] = self.query_one(f"#key-{key}", Input).value.strip()
                if values[key]:
                    os.environ[key] = values[key]
            try:
                self._write_env(values)
                status.update(
                    f"[green]Saved {sum(1 for v in values.values() if v)} keys to {ENV_FILE}[/green]"
                )
            except OSError as exc:
                status.update(f"[red]Failed to save: {exc}[/red]")
        elif event.button.id == "reload":
            current = self._read_env()
            for key in KNOWN_KEYS:
                self.query_one(f"#key-{key}", Input).value = current.get(key, "")
            status.update("[green]Reloaded from disk.[/green]")
