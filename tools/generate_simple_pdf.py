from __future__ import annotations

import re
import sys
import textwrap
from pathlib import Path


PAGE_WIDTH = 595
PAGE_HEIGHT = 842
MARGIN_X = 54
MARGIN_TOP = 58
MARGIN_BOTTOM = 58
LINE_GAP = 4


def _escape_pdf_text(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _font_for(kind: str) -> str:
    if kind == "bold":
        return "/F2"
    if kind == "mono":
        return "/F3"
    return "/F1"


def _wrap(text: str, width: int) -> list[str]:
    if not text:
        return [""]
    return textwrap.wrap(
        text,
        width=width,
        replace_whitespace=False,
        drop_whitespace=True,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]


def _markdown_to_draw_ops(markdown: str) -> list[tuple[str, str, int, int]]:
    ops: list[tuple[str, str, int, int]] = []
    in_code = False

    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()
        if line.startswith("```"):
            in_code = not in_code
            ops.append(("", "normal", 4, 0))
            continue

        if in_code:
            for wrapped in _wrap(line, 82):
                ops.append((wrapped, "mono", 8, 18))
            continue

        if not line.strip():
            ops.append(("", "normal", 5, 0))
            continue

        heading = re.match(r"^(#{1,3})\s+(.+)$", line)
        if heading:
            level = len(heading.group(1))
            text = heading.group(2)
            if level == 1:
                ops.append((text, "bold", 18, 0))
                ops.append(("", "normal", 6, 0))
            elif level == 2:
                ops.append((text, "bold", 13, 0))
            else:
                ops.append((text, "bold", 11, 0))
            continue

        bullet = re.match(r"^-\s+(.+)$", line)
        if bullet:
            for index, wrapped in enumerate(_wrap(bullet.group(1), 82)):
                prefix = "- " if index == 0 else "  "
                ops.append((prefix + wrapped, "normal", 9, 12))
            continue

        numbered = re.match(r"^(\d+)\.\s+(.+)$", line)
        if numbered:
            prefix = f"{numbered.group(1)}. "
            for index, wrapped in enumerate(_wrap(numbered.group(2), 78)):
                ops.append(((prefix if index == 0 else "   ") + wrapped, "normal", 9, 12))
            continue

        for wrapped in _wrap(line, 88):
            ops.append((wrapped, "normal", 9, 0))

    return ops


def _paginate(ops: list[tuple[str, str, int, int]]) -> list[list[tuple[str, str, int, int]]]:
    pages: list[list[tuple[str, str, int, int]]] = [[]]
    y = PAGE_HEIGHT - MARGIN_TOP

    for op in ops:
        _, _, size, _ = op
        line_height = size + LINE_GAP
        if y - line_height < MARGIN_BOTTOM and pages[-1]:
            pages.append([])
            y = PAGE_HEIGHT - MARGIN_TOP
        pages[-1].append(op)
        y -= line_height

    return pages


def _page_stream(page_ops: list[tuple[str, str, int, int]], page_number: int, total_pages: int) -> bytes:
    commands = ["BT"]
    y = PAGE_HEIGHT - MARGIN_TOP

    for text, kind, size, indent in page_ops:
        if text:
            font = _font_for(kind)
            x = MARGIN_X + indent
            commands.append(f"{font} {size} Tf")
            commands.append(f"1 0 0 1 {x} {y} Tm")
            commands.append(f"({_escape_pdf_text(text)}) Tj")
        y -= size + LINE_GAP

    footer = f"Page {page_number} of {total_pages}"
    commands.append("/F1 8 Tf")
    commands.append(f"1 0 0 1 {PAGE_WIDTH - MARGIN_X - 60} 28 Tm")
    commands.append(f"({_escape_pdf_text(footer)}) Tj")
    commands.append("ET")
    return ("\n".join(commands) + "\n").encode("latin-1", errors="replace")


def write_pdf(markdown_path: Path, pdf_path: Path) -> None:
    markdown = markdown_path.read_text(encoding="utf-8")
    ops = _markdown_to_draw_ops(markdown)
    pages = _paginate(ops)

    objects: list[bytes] = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")

    kids = " ".join(f"{3 + index * 2} 0 R" for index in range(len(pages)))
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode())

    for index, page_ops in enumerate(pages):
        page_obj_number = 3 + index * 2
        stream_obj_number = page_obj_number + 1
        page = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> "
            f"/F2 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> "
            f"/F3 << /Type /Font /Subtype /Type1 /BaseFont /Courier >> >> >> "
            f"/Contents {stream_obj_number} 0 R >>"
        )
        objects.append(page.encode())
        stream = _page_stream(page_ops, index + 1, len(pages))
        objects.append(b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"endstream")

    chunks = [b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(sum(len(chunk) for chunk in chunks))
        chunks.append(f"{number} 0 obj\n".encode())
        chunks.append(obj)
        chunks.append(b"\nendobj\n")

    xref_offset = sum(len(chunk) for chunk in chunks)
    chunks.append(f"xref\n0 {len(objects) + 1}\n".encode())
    chunks.append(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        chunks.append(f"{offset:010d} 00000 n \n".encode())
    chunks.append(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode()
    )

    pdf_path.write_bytes(b"".join(chunks))


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: generate_simple_pdf.py input.md output.pdf", file=sys.stderr)
        return 2
    write_pdf(Path(sys.argv[1]), Path(sys.argv[2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
