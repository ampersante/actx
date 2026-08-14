import hashlib
import os
import subprocess
import tempfile
import unittest

from actx_lib import tracking

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")

TS1 = 1700000000


class InsightsTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.work = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.home.cleanup()
        self.work.cleanup()

    def run_actx(self, *args):
        env = os.environ.copy()
        env["HOME"] = self.home.name
        return subprocess.run(
            [ACTX] + list(args),
            capture_output=True,
            text=True,
            cwd=self.work.name,
            env=env,
        )

    def seed(self, rows):
        os.environ["HOME"] = self.home.name
        try:
            conn = tracking.connect()
            for category, before, after, code, timestamp, passthrough in rows:
                command_hash = hashlib.sha1(
                    ("cmd %s" % category).encode("utf-8")
                ).hexdigest()
                conn.execute(
                    "INSERT INTO calls (command_hash, category, bytes_before, "
                    "bytes_after, exit_code, timestamp, passthrough) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        command_hash,
                        category,
                        before,
                        after,
                        code,
                        timestamp,
                        passthrough,
                    ),
                )
            conn.commit()
            conn.close()
        finally:
            del os.environ["HOME"]

    def test_discover_sorted_by_passthrough_frequency(self):
        self.seed(
            [
                ("docker", 5, 5, 0, TS1, 1),
                ("docker", 5, 5, 0, TS1, 1),
                ("docker", 5, 5, 0, TS1, 1),
                ("gh", 5, 5, 0, TS1, 1),
                ("gh", 5, 5, 0, TS1, 1),
                ("git", 5, 5, 0, TS1, 1),
                ("git", 20, 10, 0, TS1, 0),
            ]
        )
        p = self.run_actx("discover")
        self.assertEqual(p.returncode, 0)
        lines = p.stdout.strip().split("\n")
        self.assertEqual(lines, ["docker", "gh", "git"])

    def test_session_adoption(self):
        self.seed(
            [
                ("git", 20, 10, 0, TS1, 0),
                ("docker", 5, 5, 0, TS1 + 1000, 1),
                ("git", 30, 10, 0, TS1 + 100000, 0),
                ("run", 40, 20, 0, TS1 + 101000, 0),
            ]
        )
        p = self.run_actx("session")
        self.assertEqual(p.returncode, 0)
        self.assertIn("adoption: 50.0%", p.stdout)
        self.assertIn("adoption: 100.0%", p.stdout)

    def test_mismatched_schema_exit_zero(self):
        os.environ["HOME"] = self.home.name
        try:
            conn = tracking.connect()
            conn.execute("DROP TABLE IF EXISTS calls")
            conn.execute("CREATE TABLE calls (id INTEGER)")
            conn.commit()
            conn.close()
        finally:
            del os.environ["HOME"]
        for command in ("discover", "session"):
            p = self.run_actx(command)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(p.stdout, "")

    def test_empty_database_exit_zero(self):
        for command in ("discover", "session"):
            p = self.run_actx(command)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(p.stdout, "")


if __name__ == "__main__":
    unittest.main()
