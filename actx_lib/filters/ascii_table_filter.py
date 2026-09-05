"""Reusable ASCII bordered-table compactor for psql/mysql style output.

Detects tables drawn with +----+ frame lines and | cell rows, drops the
graphics and padding, and emits a compact CSV-like block:

    id,username,created_at
    1,alice,2026-01-15

Contract (lossy in format, lossless in values):
- Cell values are preserved verbatim once padding whitespace is stripped
  (leading/trailing padding is indistinguishable from data; documented
  approximation, same class as the grep ':' split). Values may contain
  commas -- the output is CSV-like display text, not strict CSV.
- A value containing '|' cannot be split reliably: when any row's cell
  count or interior pipe positions disagree with the header, the whole
  input is returned unchanged (raw fallback, fail-open).
- Empty table (frames with no data rows) compacts to the header line plus
  a '(0 rows)' marker; frames without any header yield just '(0 rows)'.
- Text without frame lines passes through verbatim; non-table lines
  around a table (psql command tags, mysql footers) are kept as-is.
- Never raises: any internal error returns the input unchanged. Both the
  passthrough and every fallback return the ORIGINAL object, so callers
  can detect "nothing was compacted" with `compact_table(t) is t`.

Out of scope: markdown tables, Unicode box drawing, psql border-0
aligned output (no frame lines). REGISTRY wiring arrives with the
SQL-CLI filter (TK-43); import lazily like json_compactor.
"""

import re

# Frame line: only '+', '-' (with '|' tolerated at junctions), at least one
# '-', optional trailing whitespace (psql border-2 pads a trailing space).
_FRAME_RE = re.compile(r"\+(?=[-|+]*-)[-|+]*\+[ \t]*\Z")


def _is_frame(line):
    return _FRAME_RE.match(line) is not None


def _split_row(line):
    """Split '| a | b |' into ['a', 'b']; None when not a framed cell row."""
    row = line.rstrip()
    if len(row) < 2 or not row.startswith("|") or not row.endswith("|"):
        return None
    return [cell.strip() for cell in row[1:-1].split("|")]


def _interior_pipes(line):
    """0-based '|' column indexes, excluding the left/right border pipes."""
    row = line.rstrip()
    return [i for i, ch in enumerate(row) if ch == "|"][1:-1]


def _compact_block(block):
    """Frame/content lines of one table -> compact lines; None on doubt."""
    rows = [line for line in block if not _is_frame(line)]
    if not rows:
        return ["(0 rows)"]
    header_cells = _split_row(rows[0])
    if header_cells is None:
        return None
    header_pipes = _interior_pipes(rows[0])
    lines = [",".join(header_cells)]
    data = rows[1:]
    if not data:
        lines.append("(0 rows)")
        return lines
    for row in data:
        cells = _split_row(row)
        if cells is None or len(cells) != len(header_cells):
            return None
        if _interior_pipes(row) != header_pipes:
            return None
        lines.append(",".join(cells))
    return lines


def compact_table(text):
    """Compact framed ASCII tables; return the input unchanged on any doubt."""
    try:
        if not isinstance(text, str) or "+" not in text:
            return text
        lines = text.split("\n")
        if not any(_is_frame(line) for line in lines):
            return text
        had_newline = text.endswith("\n")
        if had_newline:
            lines.pop()
        out = []
        i = 0
        while i < len(lines):
            if not _is_frame(lines[i]):
                # A pipe-bearing line directly before a frame is a table
                # row that lost its leading '|' -> doubt -> raw.
                if "|" in lines[i] and i + 1 < len(lines) and _is_frame(lines[i + 1]):
                    return text
                out.append(lines[i])
                i += 1
                continue
            j = i + 1
            while j < len(lines) and (
                _is_frame(lines[j]) or lines[j].startswith("|")
            ):
                j += 1
            block = lines[i:j]
            if len(block) == 1:
                out.append(lines[i])  # lone frame line: not a table
            elif not _is_frame(block[-1]):
                return text  # frame block never closes: doubt -> raw
            else:
                compacted = _compact_block(block)
                if compacted is None:
                    return text  # ragged '|' layout (value contains '|') -> raw
                out.extend(compacted)
            i = j
        result = "\n".join(out) + ("\n" if had_newline else "")
        return text if result == text else result
    except Exception:
        return text
