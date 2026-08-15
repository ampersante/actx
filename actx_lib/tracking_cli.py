import os
import sqlite3
import sys

from actx_lib import config, tracking

_USAGE = "usage: actx tracking [on|off|status|clear]\n"


def _status():
    cfg = config.load()
    tracking.set_enabled(tracking.configured_enabled(cfg))
    print("tracking: %s" % ("enabled" if tracking.is_enabled() else "disabled"))
    path = tracking._db_path()
    print("history.db: %s" % path)
    if os.path.exists(path):
        try:
            conn = sqlite3.connect(path)
            count = conn.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
            conn.close()
            print("calls: %d" % count)
        except sqlite3.Error:
            print("calls: 0")
    return 0


def main(args):
    if not args:
        return _status()
    if len(args) > 1:
        print("error: tracking takes at most one argument", file=sys.stderr)
        return 1
    action = args[0]
    if action == "status":
        return _status()
    if action in ("on", "off"):
        cfg = config.load()
        if not isinstance(cfg.get("tracking"), dict):
            cfg["tracking"] = {}
        cfg["tracking"]["enabled"] = (action == "on")
        try:
            config.save(cfg)
        except OSError:
            print("error: could not write config", file=sys.stderr)
            return 1
        print("tracking: %s" % action)
        return 0
    if action == "clear":
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(tracking._db_path() + suffix)
            except OSError:
                pass
        print("cleared history.db")
        return 0
    print("error: unknown tracking action: %s" % action, file=sys.stderr)
    print(_USAGE, end="", file=sys.stderr)
    return 1
