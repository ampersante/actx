import json
import os
import sqlite3
import sys
from datetime import datetime

from actx_lib import tracking

_USAGE = """usage: actx gain [--graph|--history|--daily] [--format json]
"""


def _parse_args(args):
    view = "total"
    fmt = "text"
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--format":
            if index + 1 >= len(args):
                print("error: --format requires a value", file=sys.stderr)
                return None, None
            fmt = args[index + 1]
            index += 2
            continue
        if token in ("--graph", "--history", "--daily"):
            if view != "total":
                print("error: gain views are mutually exclusive", file=sys.stderr)
                return None, None
            view = token[2:]
            index += 1
            continue
        print("error: unknown gain option: %s" % token, file=sys.stderr)
        return None, None
    if fmt not in ("text", "json"):
        print("error: unknown format: %s" % fmt, file=sys.stderr)
        return None, None
    return view, fmt


def _open():
    path = tracking._db_path()
    if not os.path.exists(path):
        return None
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute(
            "SELECT command_hash, category, bytes_before, bytes_after, "
            "exit_code, timestamp, passthrough FROM calls LIMIT 1"
        )
    except sqlite3.OperationalError:
        conn.close()
        return None
    return conn


def _saved_expression():
    return "MAX(0, bytes_before - bytes_after)"


def _total(conn):
    row = conn.execute(
        "SELECT COALESCE(SUM(%s), 0) AS saved, COUNT(*) AS calls FROM calls"
        % _saved_expression()
    ).fetchone()
    return int(row["saved"]), int(row["calls"])


def _daily(conn):
    rows = conn.execute(
        "SELECT date(timestamp, 'unixepoch', 'localtime') AS day, "
        "SUM(%s) AS saved FROM calls GROUP BY day ORDER BY day"
        % _saved_expression()
    ).fetchall()
    return [(row["day"], int(row["saved"])) for row in rows]


def _history(conn):
    rows = conn.execute(
        "SELECT timestamp, category, bytes_before, bytes_after FROM calls "
        "ORDER BY timestamp DESC LIMIT 10"
    ).fetchall()
    return [
        (
            datetime.fromtimestamp(int(row["timestamp"])).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            row["category"],
            max(0, int(row["bytes_before"]) - int(row["bytes_after"])),
        )
        for row in rows
    ]


def _fmt_total(conn):
    saved, calls = _total(conn)
    return {"total_saved_bytes": saved, "calls": calls}


def _fmt_daily(conn):
    return {
        "daily": [
            {"date": day, "saved_bytes": saved} for day, saved in _daily(conn)
        ]
    }


def _fmt_history(conn):
    return {
        "history": [
            {"timestamp": stamp, "category": category, "saved_bytes": saved}
            for stamp, category, saved in _history(conn)
        ]
    }


def _fmt_graph(conn):
    return {"graph": _fmt_daily(conn)["daily"]}


_JSON_BUILDERS = {
    "total": _fmt_total,
    "daily": _fmt_daily,
    "history": _fmt_history,
    "graph": _fmt_graph,
}


def _print_text(view, conn):
    if view == "total":
        saved, calls = _total(conn)
        print("saved: %d bytes" % saved)
        return
    if view == "daily":
        for day, saved in _daily(conn):
            print("%s: %d bytes" % (day, saved))
        return
    if view == "history":
        for stamp, category, saved in _history(conn):
            print("%s %s: %d bytes" % (stamp, category, saved))
        return
    rows = _daily(conn)
    if not rows:
        print("no data")
        return
    max_saved = max(saved for _, saved in rows)
    scale = max(1, max_saved // 10)
    for day, saved in rows:
        bar = "#" * max(0, saved // scale)
        print("%s %d %s" % (day, saved, bar))


def main(args):
    view, fmt = _parse_args(args)
    if view is None:
        print(_USAGE, end="", file=sys.stderr)
        return 1

    conn = _open()
    if conn is None:
        conn = sqlite3.connect(":memory:")
        conn.execute(
            """CREATE TABLE calls (
                command_hash TEXT, category TEXT, bytes_before INTEGER,
                bytes_after INTEGER, exit_code INTEGER, timestamp INTEGER,
                passthrough INTEGER
            )"""
        )
        conn.row_factory = sqlite3.Row
    try:
        if fmt == "json":
            print(json.dumps(_JSON_BUILDERS[view](conn)))
        else:
            _print_text(view, conn)
        return 0
    finally:
        conn.close()
