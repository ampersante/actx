import json
import os
import sqlite3
import sys
import time
from datetime import datetime

from actx_lib import tracking

_SESSION_GAP_SECONDS = 1800


def _open():
    path = tracking._db_path()
    if not os.path.exists(path):
        return None
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        tracking._migrate(conn)
        conn.execute(
            "SELECT command_hash, command_text, category, bytes_before, "
            "bytes_after, exit_code, timestamp, passthrough FROM calls LIMIT 1"
        )
    except sqlite3.OperationalError:
        conn.close()
        return None
    return conn


def _empty_conn():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        """CREATE TABLE calls (
            command_hash TEXT, command_text TEXT, category TEXT,
            bytes_before INTEGER, bytes_after INTEGER, exit_code INTEGER,
            timestamp INTEGER, passthrough INTEGER
        )"""
    )
    conn.row_factory = sqlite3.Row
    return conn


def run_discover(args):
    if args:
        print("error: discover takes no arguments", file=sys.stderr)
        return 1
    conn = _open() or _empty_conn()
    try:
        rows = conn.execute(
            "SELECT category FROM calls WHERE passthrough = 1 "
            "GROUP BY category ORDER BY COUNT(*) DESC, category ASC"
        ).fetchall()
        for row in rows:
            print(row["category"])
        return 0
    finally:
        conn.close()


def run_session(args):
    if args:
        print("error: session takes no arguments", file=sys.stderr)
        return 1
    conn = _open() or _empty_conn()
    try:
        rows = conn.execute(
            "SELECT timestamp, bytes_before, bytes_after, passthrough FROM calls "
            "ORDER BY timestamp ASC"
        ).fetchall()
        if not rows:
            return 0
        sessions = []
        current = [rows[0]]
        for row in rows[1:]:
            if row["timestamp"] - current[-1]["timestamp"] > _SESSION_GAP_SECONDS:
                sessions.append(current)
                current = [row]
            else:
                current.append(row)
        sessions.append(current)

        for session_rows in sessions:
            start = datetime.fromtimestamp(
                session_rows[0]["timestamp"]
            ).strftime("%Y-%m-%d %H:%M:%S")
            total = len(session_rows)
            filtered = sum(
                1 for row in session_rows if row["passthrough"] == 0
            )
            adoption = filtered / total * 100 if total else 0.0
            print("%s adoption: %.1f%%" % (start, adoption))
        return 0
    finally:
        conn.close()


_INSIGHTS_USAGE = (
    "usage: actx insights [--days N] [--top N] [--verbose-commands] [--json]\n"
)


def _parse_insights_args(args):
    days = 7
    top = 10
    fmt = "text"
    verbose_commands = False
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--days":
            if index + 1 >= len(args):
                return None, None, None, None
            try:
                days = int(args[index + 1])
            except ValueError:
                return None, None, None, None
            index += 2
            continue
        if token == "--top":
            if index + 1 >= len(args):
                return None, None, None, None
            try:
                top = int(args[index + 1])
            except ValueError:
                return None, None, None, None
            index += 2
            continue
        if token == "--verbose-commands":
            verbose_commands = True
            index += 1
            continue
        if token == "--json":
            fmt = "json"
            index += 1
            continue
        return None, None, None, None
    if days < 0 or top < 1:
        return None, None, None, None
    return days, top, fmt, verbose_commands


def _repeated(conn, cutoff, top):
    return conn.execute(
        "SELECT command_text, COUNT(*) AS n, "
        "COALESCE(SUM(MAX(0, bytes_before - bytes_after)), 0) AS saved "
        "FROM calls WHERE timestamp >= ? AND command_text != '' "
        "GROUP BY command_text ORDER BY n DESC, saved DESC LIMIT ?",
        (cutoff, top),
    ).fetchall()


def _failing(conn, cutoff, top):
    return conn.execute(
        "SELECT command_text, COUNT(*) AS n, MAX(exit_code) AS last_exit "
        "FROM calls WHERE timestamp >= ? AND exit_code != 0 "
        "AND command_text != '' "
        "GROUP BY command_text ORDER BY n DESC, last_exit DESC LIMIT ?",
        (cutoff, top),
    ).fetchall()


def _passthrough(conn, cutoff, top):
    return conn.execute(
        "SELECT command_text, COUNT(*) AS n, SUM(bytes_before) AS raw "
        "FROM calls WHERE timestamp >= ? AND passthrough = 1 "
        "AND command_text != '' "
        "GROUP BY command_text ORDER BY raw DESC, n DESC LIMIT ?",
        (cutoff, top),
    ).fetchall()


def _suggestions(repeated):
    suggestions = []
    cat_counts = {}
    for row in repeated:
        text = row["command_text"]
        n = int(row["n"])
        if text.startswith("git log"):
            tokens = text.split()
            if not any(
                t == "-1" or t.startswith("-n") or t.startswith("--max-count")
                for t in tokens
            ):
                suggestions.append("git log без -n: укажите -n N — %s" % text)
        if text.startswith("find . -name") and "-maxdepth" not in text:
            suggestions.append(
                "find по всему дереву: укажите -maxdepth или путь — %s" % text
            )
        if text.startswith("cat "):
            tokens = text.split()
            if len(tokens) >= 2:
                file = tokens[-1]
                cat_counts[file] = cat_counts.get(file, 0) + n
    for file, n in cat_counts.items():
        if n >= 3:
            suggestions.append(
                "файл читается %d раз: рассмотрите однократное чтение — %s"
                % (n, file)
            )
    return sorted(set(suggestions))


def _suggested_convention(head):
    """Advice line for a head from the shared conventions table, or None
    (single source with hook/Tier-2, REQ-01/INV-01 - heads without a
    CONVENTIONS record get no invented advice, W-F11)."""
    from actx_lib import conventions

    entries = conventions.CONVENTIONS.get(head)
    if not entries:
        return None
    return entries[0][2]


def _verbose(conn, cutoff, top):
    """Heads with the largest raw (unfiltered) output - category level only,
    command_text never leaves the DB in this report (REQ-05b)."""
    return conn.execute(
        "SELECT category, COUNT(*) AS n, SUM(bytes_before) AS raw "
        "FROM calls WHERE timestamp >= ? AND passthrough = 1 "
        "GROUP BY category ORDER BY raw DESC, category ASC LIMIT ?",
        (cutoff, top),
    ).fetchall()


def _adoption(conn):
    """Per wave-1-2 head: share of actx-mediated calls that were compressed.
    Exit 124/125 rows are excluded from BOTH terms - actx-internal
    refusals/timeouts are not an agent's choice to skip compression
    (H-F5/N-F6). Heads with zero observable calls are omitted (W-F10)."""
    from actx_lib import conventions

    rows = conn.execute(
        "SELECT category, COUNT(*) AS calls, "
        "SUM(CASE WHEN passthrough = 0 THEN 1 ELSE 0 END) AS compressed "
        "FROM calls WHERE exit_code NOT IN (124, 125) GROUP BY category"
    ).fetchall()
    by_head = {
        row["category"]: (int(row["calls"]), int(row["compressed"]))
        for row in rows
        if row["category"] in conventions.WAVE_HEADS
    }
    report = [
        (head, calls, compressed)
        for head, (calls, compressed) in by_head.items()
        if calls > 0
    ]
    report.sort(key=lambda item: (-item[1], item[0]))
    return report


def _print_insights_text(repeated, failing, passthrough, suggestions,
                          verbose, adoption):
    print("repeated:")
    if repeated:
        for r in repeated:
            print(
                "  %d calls  %d bytes saved  %s"
                % (r["n"], r["saved"], r["command_text"])
            )
    else:
        print("  none")
    print("failing:")
    if failing:
        for r in failing:
            print(
                "  %d failures  last exit %d  %s"
                % (r["n"], r["last_exit"], r["command_text"])
            )
    else:
        print("  none")
    print("passthrough:")
    if passthrough:
        for r in passthrough:
            print(
                "  %d calls  %d raw bytes  %s"
                % (r["n"], r["raw"], r["command_text"])
            )
    else:
        print("  none")
    print("suggestions:")
    if suggestions:
        for s in suggestions:
            print("  " + s)
    else:
        print("  none")
    print(
        "adoption: share of compressed among actx-mediated calls "
        "(calls bypassing actx are not observed; exits 124/125 excluded)"
    )
    if adoption:
        for head, calls, compressed in adoption:
            print(
                "  %s: %d calls, %d compressed, %.0f%%"
                % (head, calls, compressed, compressed / calls * 100)
            )
    else:
        print("  none")
    if verbose is not None:
        print("verbose_commands:")
        if verbose:
            for row in verbose:
                suggested = _suggested_convention(row["category"])
                print(
                    "  %s  %d calls  %d raw bytes  suggested: %s"
                    % (
                        row["category"],
                        int(row["n"]),
                        int(row["raw"]),
                        suggested if suggested else "none",
                    )
                )
        else:
            print("  none")


def run_insights(args):
    days, top, fmt, verbose_commands = _parse_insights_args(args)
    if days is None:
        print(_INSIGHTS_USAGE, end="", file=sys.stderr)
        return 1
    conn = _open() or _empty_conn()
    try:
        cutoff = int(time.time()) - days * 86400
        repeated = _repeated(conn, cutoff, top)
        failing = _failing(conn, cutoff, top)
        passthrough = _passthrough(conn, cutoff, top)
        suggestions = _suggestions(repeated)
        adoption = _adoption(conn)
        verbose = _verbose(conn, cutoff, top) if verbose_commands else None
        if fmt == "json":
            print(
                json.dumps(
                    {
                        "days": days,
                        "top": top,
                        "repeated": [
                            {
                                "command": r["command_text"],
                                "calls": int(r["n"]),
                                "saved_bytes": int(r["saved"]),
                            }
                            for r in repeated
                        ],
                        "failing": [
                            {
                                "command": r["command_text"],
                                "failures": int(r["n"]),
                                "last_exit": int(r["last_exit"]),
                            }
                            for r in failing
                        ],
                        "passthrough": [
                            {
                                "command": r["command_text"],
                                "calls": int(r["n"]),
                                "raw_bytes": int(r["raw"]),
                            }
                            for r in passthrough
                        ],
                        "suggestions": suggestions,
                        "adoption": [
                            {
                                "head": head,
                                "calls": calls,
                                "compressed": compressed,
                                "adoption_pct": compressed / calls * 100,
                            }
                            for head, calls, compressed in adoption
                        ],
                        "verbose_commands": [
                            {
                                "head": r["category"],
                                "calls": int(r["n"]),
                                "raw_bytes": int(r["raw"]),
                                "suggested": _suggested_convention(
                                    r["category"]
                                ),
                            }
                            for r in (verbose or [])
                        ],
                    }
                )
            )
        else:
            _print_insights_text(
                repeated, failing, passthrough, suggestions, verbose, adoption
            )
        return 0
    finally:
        conn.close()
