import hashlib
import os
import sqlite3
import time

_DB_PATH = "~/.local/share/actx/history.db"


def _join_cmd(cmd):
    return " ".join(cmd)


def _db_path():
    return os.path.expanduser(_DB_PATH)


def connect():
    """Open the history database, creating schema if needed."""
    path = _db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS calls (
            command_hash TEXT NOT NULL,
            category TEXT NOT NULL,
            bytes_before INTEGER NOT NULL,
            bytes_after INTEGER NOT NULL,
            exit_code INTEGER NOT NULL,
            timestamp INTEGER NOT NULL,
            passthrough INTEGER NOT NULL DEFAULT 0
        )"""
    )
    return conn


def record(cmd, category, bytes_before, bytes_after, exit_code, passthrough=0):
    """Store an aggregate; never the full command. Fail-open: any storage
    error is silently ignored so it cannot affect the command's exit code."""
    try:
        command_hash = hashlib.sha1(_join_cmd(cmd).encode("utf-8")).hexdigest()
        conn = connect()
        try:
            conn.execute(
                "INSERT INTO calls (command_hash, category, bytes_before, "
                "bytes_after, exit_code, timestamp, passthrough) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    command_hash,
                    category,
                    int(bytes_before),
                    int(bytes_after),
                    int(exit_code),
                    int(time.time()),
                    int(passthrough),
                ),
            )
            conn.commit()
        finally:
            conn.close()
    except Exception:
        pass
