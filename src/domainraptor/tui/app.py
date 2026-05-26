"""DomainRaptor Textual TUI application."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Label, ListItem, ListView

from domainraptor import __version__
from domainraptor.tui.screens.assess import AssessScreen
from domainraptor.tui.screens.compare import CompareScreen
from domainraptor.tui.screens.config import ConfigScreen
from domainraptor.tui.screens.dashboard import DashboardScreen
from domainraptor.tui.screens.database import DatabaseScreen
from domainraptor.tui.screens.discover import DiscoverScreen
from domainraptor.tui.screens.enrich_screen import EnrichScreen
from domainraptor.tui.screens.exploit_screen import ExploitScreen
from domainraptor.tui.screens.recon import ReconScreen
from domainraptor.tui.screens.reports import ReportsScreen
from domainraptor.tui.screens.watch import WatchScreen

SCREENS = [
    ("dashboard", "🏠 Dashboard", DashboardScreen),
    ("discover", "🔍 Discover", DiscoverScreen),
    ("recon", "🎯 Recon", ReconScreen),
    ("assess", "🛡️  Assess", AssessScreen),
    ("exploits", "🧨 Exploits", ExploitScreen),
    ("enrich", "🔬 Enrich", EnrichScreen),
    ("compare", "📊 Compare", CompareScreen),
    ("watch", "👁️  Watch", WatchScreen),
    ("reports", "📄 Reports", ReportsScreen),
    ("database", "💾 Database", DatabaseScreen),
    ("config", "⚙️  Config", ConfigScreen),
]


class DomainRaptorApp(App):
    """Main Textual application for DomainRaptor."""

    CSS_PATH = "styles.tcss"
    TITLE = "DomainRaptor"
    SUB_TITLE = f"Cyber Intelligence Tool v{__version__}"

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("ctrl+c", "quit", "Quit", show=False, priority=True),
        Binding("d", "switch('dashboard')", "Dashboard"),
        Binding("s", "switch('discover')", "Discover"),
        Binding("r", "switch('recon')", "Recon"),
        Binding("a", "switch('assess')", "Assess"),
        Binding("e", "switch('exploits')", "Exploits"),
        Binding("n", "switch('enrich')", "Enrich"),
        Binding("w", "switch('watch')", "Watch"),
        Binding("b", "switch('database')", "DB"),
        Binding("c", "switch('config')", "Config"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._current_screen_id: str = "dashboard"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Label("🦎 DomainRaptor", classes="banner")
                yield ListView(
                    *[ListItem(Label(label), id=f"nav-{key}") for key, label, _ in SCREENS],
                    id="nav-list",
                )
            with Vertical(id="main"):
                yield DashboardScreen(id="screen-dashboard")
        yield Footer()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle sidebar selection."""
        if event.item is None or event.item.id is None:
            return
        key = event.item.id.replace("nav-", "")
        self.action_switch(key)

    def action_switch(self, screen_key: str) -> None:
        """Switch the main content area to a different screen widget."""
        if screen_key == self._current_screen_id:
            return

        screen_cls = None
        for key, _label, cls in SCREENS:
            if key == screen_key:
                screen_cls = cls
                break
        if screen_cls is None:
            return

        main = self.query_one("#main", Vertical)
        # Remove current content (Header bar will repaint automatically)
        for child in list(main.children):
            child.remove()
        main.mount(screen_cls(id=f"screen-{screen_key}"))
        self._current_screen_id = screen_key

        # Sync sidebar highlight
        nav = self.query_one("#nav-list", ListView)
        for idx, (key, _label, _cls) in enumerate(SCREENS):
            if key == screen_key:
                nav.index = idx
                break


def run_tui() -> None:
    """Entry point to launch the TUI."""
    # Ensure env keys are loaded just like the CLI does
    env_file = Path.home() / ".domainraptor" / ".env"
    if env_file.exists():
        import os

        with env_file.open() as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if key not in os.environ:
                        os.environ[key] = value

    DomainRaptorApp().run()


if __name__ == "__main__":
    run_tui()
