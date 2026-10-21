"""A small PDF writer for text, tables and filled boxes using the standard Helvetica fonts."""

from __future__ import annotations

import textwrap

WIDTH, HEIGHT, MARGIN = 595, 842, 48
INK = (0.13, 0.15, 0.2)
MUTED = (0.42, 0.45, 0.5)
RULE = (0.86, 0.88, 0.91)
HEADER_FILL = (0.94, 0.95, 0.97)
BRAND = (0.11, 0.3, 0.62)

# Average Helvetica glyph width as a fraction of the font size.
_GLYPH = 0.5


def _escape(text: str) -> str:
    """PDF literal-string body in WinAnsi encoding; characters outside it become "?"."""
    raw = str(text).encode("cp1252", errors="replace").decode("latin-1")
    out = []
    for char in raw:
        if char in "\\()":
            out.append("\\" + char)
        elif ord(char) < 32:
            out.append(" ")
        else:
            out.append(char)
    return "".join(out)


def _fit(text: str, width: float, size: float) -> str:
    limit = max(int(width / (size * _GLYPH)), 4)
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _rgb(color: tuple[float, float, float]) -> str:
    return " ".join(f"{part:.3f}" for part in color)


class Document:
    """Lays content out top to bottom, starting a new A4 page when one fills up."""

    def __init__(self, title: str) -> None:
        self.title = title
        self.pages: list[list[str]] = []
        self.y = 0.0
        self._page()

    def _page(self) -> None:
        self.ops: list[str] = []
        self.pages.append(self.ops)
        self.y = HEIGHT - MARGIN

    def _room(self, height: float) -> None:
        if self.y - height < MARGIN + 20:
            self._page()

    def text(self, x: float, y: float, text: str, size: float = 10, bold: bool = False, color=INK) -> None:
        font = "F2" if bold else "F1"
        self.ops.append(f"BT /{font} {size} Tf {_rgb(color)} rg {x:.1f} {y:.1f} Td ({_escape(text)}) Tj ET")

    def box(self, x: float, y: float, width: float, height: float, color) -> None:
        self.ops.append(f"{_rgb(color)} rg {x:.1f} {y:.1f} {width:.1f} {height:.1f} re f")

    def heading(self, text: str, size: float = 14) -> None:
        self._room(size + 26)
        self.y -= size + 14
        self.text(MARGIN, self.y, text, size, bold=True)
        self.y -= 6
        self.box(MARGIN, self.y, WIDTH - 2 * MARGIN, 0.8, RULE)
        self.y -= 4

    def paragraph(self, text: str, size: float = 10, color=INK) -> None:
        limit = int((WIDTH - 2 * MARGIN) / (size * _GLYPH))
        for line in textwrap.wrap(" ".join(str(text).split()), limit) or [""]:
            self._room(size + 4)
            self.y -= size + 4
            self.text(MARGIN, self.y, line, size, color=color)

    def gap(self, height: float = 8) -> None:
        self.y -= height

    def tiles(self, items: list[tuple[str, str]]) -> None:
        """A row of labelled values, such as headline scores."""
        self._room(56)
        width = (WIDTH - 2 * MARGIN - 8 * (len(items) - 1)) / max(len(items), 1)
        top = self.y - 6
        for index, (label, value) in enumerate(items):
            x = MARGIN + index * (width + 8)
            self.box(x, top - 46, width, 46, HEADER_FILL)
            self.text(x + 8, top - 18, _fit(value, width - 16, 15), 15, bold=True, color=BRAND)
            self.text(x + 8, top - 36, _fit(label, width - 16, 8), 8, color=MUTED)
        self.y = top - 52

    def table(self, headers: list[str], rows: list[list[str]], widths: list[float]) -> None:
        """Columns sized as fractions of the page width; the header repeats on each page."""
        size, height = 8.5, 15
        usable = WIDTH - 2 * MARGIN
        columns = [usable * fraction for fraction in widths]

        def header() -> None:
            self.y -= height
            self.box(MARGIN, self.y - 4, usable, height, HEADER_FILL)
            self._cells(headers, columns, size, bold=True)

        self._room(height * 2)
        header()
        for row in rows:
            if self.y - height < MARGIN + 20:
                self._page()
                header()
            self.y -= height
            self._cells(row, columns, size)
            self.box(MARGIN, self.y - 5, usable, 0.5, RULE)

    def _cells(self, values: list[str], columns: list[float], size: float, bold: bool = False) -> None:
        x = MARGIN
        for value, width in zip(values, columns, strict=False):
            self.text(x + 4, self.y, _fit(value, width - 8, size), size, bold=bold)
            x += width

    def render(self) -> bytes:
        total = len(self.pages)
        for number, ops in enumerate(self.pages, start=1):
            self.ops = ops
            self.text(MARGIN, MARGIN - 18, _fit(self.title, 380, 8), 8, color=MUTED)
            self.text(WIDTH - MARGIN - 70, MARGIN - 18, f"Page {number} of {total}", 8, color=MUTED)

        objects = [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
            f"<< /Title ({_escape(self.title)}) /Producer (SecGuard) >>",
        ]
        kids = []
        for ops in self.pages:
            stream = "\n".join(ops)
            objects.append(f"<< /Length {len(stream.encode('latin-1'))} >>\nstream\n{stream}\nendstream")
            objects.append(
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {WIDTH} {HEIGHT}] "
                f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {len(objects)} 0 R >>"
            )
            kids.append(f"{len(objects)} 0 R")
        objects[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {total} >>"

        output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for number, body in enumerate(objects, start=1):
            offsets.append(len(output))
            output += f"{number} 0 obj\n{body}\nendobj\n".encode("latin-1")
        xref = len(output)
        output += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("latin-1")
        output += "".join(f"{offset:010d} 00000 n \n" for offset in offsets).encode("latin-1")
        output += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info 5 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("latin-1")
        return bytes(output)
