"""Pretty in-TUI preview rendering for report files.

Converts HTML / Markdown / JSON / YAML / CSV into Rich renderables that mimic
a browser-style report inside the terminal (headings, tables, lists, code).
PDFs are not previewable in the terminal.
"""

from __future__ import annotations

import csv
import io
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from rich.console import Group, RenderableType
from rich.markdown import Markdown
from rich.padding import Padding
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

# Tags whose textual content must be discarded entirely.
_SKIP_CONTENT_TAGS = {"style", "script", "svg", "noscript", "head", "meta", "link"}
_BLOCK_TAGS = {
    "p",
    "div",
    "section",
    "article",
    "header",
    "footer",
    "main",
    "nav",
    "aside",
    "br",
}
_HEADING_STYLES = {
    "h1": ("bold magenta", "═"),
    "h2": ("bold cyan", "─"),
    "h3": ("bold yellow", "·"),
    "h4": ("bold green", "·"),
    "h5": ("bold", " "),
    "h6": ("bold", " "),
}


class _HTMLToRich(HTMLParser):
    """Translate a subset of HTML into a sequence of Rich renderables."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.renderables: list[RenderableType] = []
        # Inline buffer accumulates Text for the current paragraph/heading/cell.
        self._inline: Text = Text()
        self._style_stack: list[str] = []
        self._skip_depth = 0
        # Block context stack ("h1"/"p"/"li"/"td"/"th"/"pre"/...).
        self._block_stack: list[str] = []
        # List context stack: (kind, counter) where kind ∈ {"ul","ol"}.
        self._list_stack: list[tuple[str, int]] = []
        # Table state: rows -> list of cells (each cell is a Text), headers flag.
        self._tables: list[dict[str, Any]] = []
        self._link_href: str | None = None

    # ---------- helpers ----------

    def _flush_inline_into(self, target: list[RenderableType] | None = None) -> Text | None:
        if not self._inline.plain.strip():
            self._inline = Text()
            return None
        text = self._inline
        self._inline = Text()
        if target is None:
            self.renderables.append(text)
            return None
        target.append(text)
        return text

    def _append_text(self, data: str) -> None:
        if self._skip_depth:
            return
        if not data:
            return
        style = " ".join(self._style_stack) if self._style_stack else ""
        # Inside <pre> keep whitespace exactly; elsewhere collapse runs.
        if "pre" not in self._block_stack:
            data = " ".join(data.split())
            if not data:
                return
            # Avoid leading space when buffer empty
            if not self._inline.plain or self._inline.plain.endswith((" ", "\n")):
                data = data.lstrip()
                if not data:
                    return
            if self._inline.plain and not self._inline.plain.endswith(" "):
                self._inline.append(" ")
        self._inline.append(data, style=style or None)

    # ---------- HTMLParser hooks ----------

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP_CONTENT_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        attrd = dict(attrs)

        if tag in _HEADING_STYLES:
            self._flush_inline_into()
            self._block_stack.append(tag)
            return
        if tag == "p" or tag in _BLOCK_TAGS:
            if tag == "br":
                self._inline.append("\n")
                return
            self._flush_inline_into()
            self._block_stack.append(tag)
            return
        if tag in {"strong", "b"}:
            self._style_stack.append("bold")
            return
        if tag in {"em", "i"}:
            self._style_stack.append("italic")
            return
        if tag == "u":
            self._style_stack.append("underline")
            return
        if tag == "code" and "pre" not in self._block_stack:
            self._style_stack.append("bold cyan on grey15")
            return
        if tag == "pre":
            self._flush_inline_into()
            self._block_stack.append("pre")
            return
        if tag == "a":
            href = attrd.get("href") or ""
            self._link_href = href
            self._style_stack.append("underline blue")
            return
        if tag in {"ul", "ol"}:
            self._flush_inline_into()
            self._list_stack.append((tag, 0))
            return
        if tag == "li":
            self._flush_inline_into()
            kind, idx = self._list_stack[-1] if self._list_stack else ("ul", 0)
            idx += 1
            if self._list_stack:
                self._list_stack[-1] = (kind, idx)
            bullet = f"{idx}. " if kind == "ol" else "• "
            self._inline.append(bullet, style="cyan")
            self._block_stack.append("li")
            return
        if tag == "table":
            self._flush_inline_into()
            self._tables.append(
                {
                    "rows": [],
                    "current_row": None,
                    "has_header": False,
                    "title": attrd.get("title") or attrd.get("summary"),
                }
            )
            self._block_stack.append("table")
            return
        if tag == "tr":
            if self._tables:
                self._tables[-1]["current_row"] = []
            return
        if tag in {"td", "th"}:
            self._flush_inline_into()
            self._block_stack.append(tag)
            if tag == "th" and self._tables:
                self._tables[-1]["has_header"] = True
                self._style_stack.append("bold")
            return
        if tag == "hr":
            self._flush_inline_into()
            self.renderables.append(Rule(style="dim"))
            return
        if tag == "img":
            alt = attrd.get("alt") or attrd.get("src") or "image"
            self._inline.append(f"🖼  {alt} ", style="italic dim")
            return
        # Generic span/other inline tags: no-op (styles applied via class are ignored).

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_CONTENT_TAGS:
            if self._skip_depth:
                self._skip_depth -= 1
            return
        if self._skip_depth:
            return

        if tag in _HEADING_STYLES:
            style, char = _HEADING_STYLES[tag]
            text = self._inline.plain.strip()
            self._inline = Text()
            if text:
                if tag in {"h1", "h2"}:
                    self.renderables.append(Rule(Text(text, style=style), characters=char))
                else:
                    self.renderables.append(Text(text, style=style))
            self._pop_block(tag)
            return
        if tag == "p" or tag in _BLOCK_TAGS:
            self._flush_inline_into()
            self._pop_block(tag)
            return
        if tag in {"strong", "b", "em", "i", "u", "code"}:
            if self._style_stack:
                self._style_stack.pop()
            return
        if tag == "pre":
            code = self._inline.plain
            self._inline = Text()
            if code.strip():
                self.renderables.append(
                    Panel(
                        Syntax(code, "text", theme="monokai", word_wrap=True),
                        border_style="dim",
                    )
                )
            self._pop_block("pre")
            return
        if tag == "a":
            if self._style_stack:
                self._style_stack.pop()
            if self._link_href:
                self._inline.append(f" ({self._link_href})", style="dim")
            self._link_href = None
            return
        if tag in {"ul", "ol"}:
            self._flush_inline_into()
            if self._list_stack:
                self._list_stack.pop()
            return
        if tag == "li":
            self._flush_inline_into()
            self._pop_block("li")
            return
        if tag in {"td", "th"}:
            cell = self._inline
            self._inline = Text()
            if tag == "th" and self._style_stack and self._style_stack[-1] == "bold":
                self._style_stack.pop()
            if self._tables and self._tables[-1]["current_row"] is not None:
                self._tables[-1]["current_row"].append(cell)
            self._pop_block(tag)
            return
        if tag == "tr":
            if self._tables and self._tables[-1]["current_row"] is not None:
                self._tables[-1]["rows"].append(self._tables[-1]["current_row"])
                self._tables[-1]["current_row"] = None
            return
        if tag == "table":
            tdata = self._tables.pop() if self._tables else None
            self._pop_block("table")
            if not tdata or not tdata["rows"]:
                return
            self.renderables.append(_build_rich_table(tdata))
            return

    def handle_data(self, data: str) -> None:
        self._append_text(data)

    def _pop_block(self, tag: str) -> None:
        # Pop the topmost matching block, tolerant to malformed HTML.
        for i in range(len(self._block_stack) - 1, -1, -1):
            if self._block_stack[i] == tag:
                del self._block_stack[i]
                return

    def finalize(self) -> list[RenderableType]:
        self._flush_inline_into()
        return self.renderables


def _build_rich_table(tdata: dict) -> RenderableType:
    rows: list[list[Text]] = tdata["rows"]
    has_header: bool = tdata["has_header"]
    title = tdata.get("title")
    table = Table(
        title=title,
        show_header=has_header,
        header_style="bold magenta",
        border_style="cyan",
        expand=True,
    )
    width = max(len(r) for r in rows)
    if has_header:
        header = rows[0]
        for i in range(width):
            label = header[i].plain if i < len(header) else ""
            table.add_column(label or f"col{i + 1}")
        body = rows[1:]
    else:
        for i in range(width):
            table.add_column(f"col{i + 1}")
        body = rows
    for row in body:
        cells: list[RenderableType] = list(row)
        while len(cells) < width:
            cells.append(Text(""))
        table.add_row(*cells)
    return table


def html_to_renderables(html: str) -> list[RenderableType]:
    parser = _HTMLToRich()
    parser.feed(html)
    parser.close()
    return parser.finalize()


def csv_to_table(raw: str, *, title: str | None = None) -> RenderableType:
    reader = csv.reader(io.StringIO(raw))
    rows = list(reader)
    if not rows:
        return Text("[empty CSV]", style="dim")
    table = Table(
        title=title,
        show_header=True,
        header_style="bold magenta",
        border_style="cyan",
        expand=True,
    )
    for col in rows[0]:
        table.add_column(col or " ")
    for row in rows[1:]:
        padded = list(row) + [""] * (len(rows[0]) - len(row))
        table.add_row(*padded[: len(rows[0])])
    return table


def render_preview(path: Path) -> RenderableType:
    """Return a Rich renderable representing a pretty preview of `path`."""
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return Panel(
            Text(
                "PDF preview is not supported in the TUI.\nOpen the file externally.",
                justify="center",
            ),
            title="PDF",
            border_style="yellow",
        )
    try:
        raw = path.read_text(errors="replace")
    except OSError as exc:
        return Panel(Text(f"Read error: {exc}", style="red"), border_style="red")

    if suffix in {".html", ".htm"}:
        renderables = html_to_renderables(raw)
        if not renderables:
            return Text("[empty HTML]", style="dim")
        # Wrap in a padded group so it looks like a document.
        return Padding(Group(*renderables), (1, 2))
    if suffix in {".md", ".markdown"}:
        return Padding(Markdown(raw, code_theme="monokai"), (1, 2))
    if suffix == ".json":
        return Syntax(raw, "json", theme="monokai", line_numbers=True, word_wrap=True)
    if suffix in {".yaml", ".yml"}:
        return Syntax(raw, "yaml", theme="monokai", line_numbers=True, word_wrap=True)
    if suffix == ".csv":
        return csv_to_table(raw, title=path.name)
    # Fallback: plain text with line numbers.
    return Syntax(raw, "text", theme="monokai", line_numbers=True, word_wrap=True)
