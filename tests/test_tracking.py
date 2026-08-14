import hashlib
import io
import os
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib import runner, tracking

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")

CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}


class TrackingTests(unittest.TestCase):
    def _db_path(self, home):
        return os.path.join(home, ".local", "share", "actx", "history.db")

    def test_schema_has_no_full_command_column(self):
        home = tempfile.TemporaryDirectory()
        os.environ["HOME"] = home.name
        try:
            tracking.record(["git", "status"], "git", 100, 50, 0)
        finally:
            del os.environ["HOME"]
        conn = sqlite3.connect(self._db_path(home.name))
        columns = [row[1] for row in conn.execute("PRAGMA table_info(calls)")]
        conn.close()
        home.cleanup()
        self.assertIn("command_hash", columns)
        self.assertNotIn("command", columns)
        self.assertNotIn("full_command", columns)
        self.assertNotIn("args", columns)

    def test_command_hash_is_reproducible(self):
        home = tempfile.TemporaryDirectory()
        os.environ["HOME"] = home.name
        try:
            tracking.record(["git", "status"], "git", 10, 5, 0)
            tracking.record(["git", "status"], "git", 10, 5, 0)
        finally:
            del os.environ["HOME"]
        conn = sqlite3.connect(self._db_path(home.name))
        rows = list(conn.execute("SELECT command_hash FROM calls"))
        conn.close()
        home.cleanup()
        expected = hashlib.sha1("git status".encode("utf-8")).hexdigest()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row[0] == expected for row in rows))

    def test_run_records_bytes_before_after_and_exit_code(self):
        home = tempfile.TemporaryDirectory()
        work = tempfile.TemporaryDirectory()
        env = os.environ.copy()
        env["HOME"] = home.name
        p = subprocess.run(
            [ACTX, "run", "python3", "-c", "print('hello')"],
            capture_output=True,
            text=True,
            cwd=work.name,
            env=env,
        )
        self.assertEqual(p.returncode, 0)
        conn = sqlite3.connect(self._db_path(home.name))
        rows = list(
            conn.execute(
                "SELECT category, bytes_before, bytes_after, exit_code FROM calls"
            )
        )
        conn.close()
        self.assertEqual(len(rows), 1)
        category, before, after, code = rows[0]
        self.assertEqual(category, "python3")
        self.assertEqual(before, 6)
        self.assertEqual(after, 6)
        self.assertEqual(code, 0)
        home.cleanup()
        work.cleanup()

    def test_storage_error_does_not_change_exit_code(self):
        with mock.patch("actx_lib.tracking.connect", side_effect=OSError("boom")):
            out = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = runner.run(["python3", "-c", "print('hi')"], CONFIG)
        self.assertEqual(rc, 0)
        self.assertIn("hi", out.getvalue())


if __name__ == "__main__":
    unittest.main()
