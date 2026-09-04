import hashlib
import os
import sqlite3
import time

_DB_PATH = "~/.local/share/actx/history.db"

_ENABLED = True
_RETENTION_DAYS = 90


def _join_cmd(cmd):
    return " ".join(cmd)


def _db_path():
    return os.path.expanduser(_DB_PATH)


def set_enabled(enabled):
    global _ENABLED
    _ENABLED = bool(enabled)


def set_retention_days(days):
    global _RETENTION_DAYS
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = 90
    _RETENTION_DAYS = days if days >= 0 else 90


def configured_enabled(cfg):
    tracking_cfg = cfg.get("tracking")
    return tracking_cfg.get("enabled", True) if isinstance(tracking_cfg, dict) else True


def configured_retention_days(cfg):
    tracking_cfg = cfg.get("tracking")
    if not isinstance(tracking_cfg, dict):
        return 90
    try:
        days = int(tracking_cfg.get("history_days", 90))
    except (TypeError, ValueError):
        return 90
    return days if days >= 0 else 90


def is_enabled():
    return _ENABLED and os.environ.get("ACTX_TRACKING") != "0"


def _migrate(conn):
    columns = {row[1] for row in conn.execute("PRAGMA table_info(calls)")}
    if "strategy" not in columns:
        conn.execute(
            "ALTER TABLE calls ADD COLUMN strategy TEXT NOT NULL DEFAULT ''"
        )
    if "command_text" not in columns:
        conn.execute(
            "ALTER TABLE calls ADD COLUMN command_text TEXT NOT NULL DEFAULT ''"
        )


def connect():
    """Open the history database, creating schema if needed."""
    path = _db_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS calls (
            command_hash TEXT NOT NULL,
            command_text TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL,
            bytes_before INTEGER NOT NULL,
            bytes_after INTEGER NOT NULL,
            exit_code INTEGER NOT NULL,
            timestamp INTEGER NOT NULL,
            passthrough INTEGER NOT NULL DEFAULT 0,
            strategy TEXT NOT NULL DEFAULT ''
        )"""
    )
    _migrate(conn)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_calls_timestamp ON calls(timestamp)"
    )
    try:
        os.chmod(os.path.dirname(path), 0o700)
        os.chmod(path, 0o600)
    except OSError:
        pass
    return conn


def record(cmd, category, bytes_before, bytes_after, exit_code, passthrough=0, strategy="",
           store_text=True):
    """Store an aggregate; never the full command. store_text=False keeps the
    command out of history (e.g. secret-bearing output); the column is NOT NULL
    so an empty string is written. Fail-open: any storage
    error is silently ignored so it cannot affect the command's exit code."""
    if not is_enabled():
        return
    strategy = strategy or ""
    try:
        command_hash = hashlib.sha1(_join_cmd(cmd).encode("utf-8")).hexdigest()
        conn = connect()
        try:
            conn.execute(
                "INSERT INTO calls (command_hash, command_text, category, "
                "bytes_before, bytes_after, exit_code, timestamp, passthrough, "
                "strategy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    command_hash,
                    _join_cmd(cmd)[:4096] if store_text else "",
                    category,
                    int(bytes_before),
                    int(bytes_after),
                    int(exit_code),
                    int(time.time()),
                    int(passthrough),
                    strategy,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        if _RETENTION_DAYS > 0:
            try:
                conn = connect()
                try:
                    cutoff = int(time.time()) - _RETENTION_DAYS * 86400
                    conn.execute("DELETE FROM calls WHERE timestamp < ?", (cutoff,))
                    conn.commit()
                finally:
                    conn.close()
            except Exception:
                pass
    except Exception:
        pass
