import os
import sqlite3
import sys
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
        conn.execute(
            "SELECT command_hash, category, bytes_before, bytes_after, "
            "exit_code, timestamp, passthrough FROM calls LIMIT 1"
        )
    except sqlite3.OperationalError:
        conn.close()
        return None
    return conn


def _empty_conn():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        """CREATE TABLE calls (
            command_hash TEXT, category TEXT, bytes_before INTEGER,
            bytes_after INTEGER, exit_code INTEGER, timestamp INTEGER,
            passthrough INTEGER
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
