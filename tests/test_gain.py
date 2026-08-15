import hashlib
import json
import os
import subprocess
import tempfile
import unittest

from actx_lib import tracking

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")

TS1 = 1700000000
TS2 = TS1 + 86400


class GainTests(unittest.TestCase):
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
            for category, before, after, code, timestamp in rows:
                command_hash = hashlib.sha1(
                    ("cmd %s" % category).encode("utf-8")
                ).hexdigest()
                conn.execute(
                    "INSERT INTO calls (command_hash, category, bytes_before, "
                    "bytes_after, exit_code, timestamp, passthrough) "
                    "VALUES (?, ?, ?, ?, ?, ?, 0)",
                    (command_hash, category, before, after, code, timestamp),
                )
            conn.commit()
            conn.close()
        finally:
            del os.environ["HOME"]

    def test_total_json(self):
        self.seed(
            [
                ("git", 10, 5, 0, TS1),
                ("git", 5, 10, 0, TS1),
                ("run", 100, 40, 0, TS1),
            ]
        )
        p = self.run_actx("gain", "--format", "json")
        self.assertEqual(p.returncode, 0)
        data = json.loads(p.stdout)
        self.assertEqual(data["total_saved_bytes"], 65)
        self.assertEqual(data["calls"], 3)
        self.assertEqual(data["estimated_tokens"], 16)
        self.assertEqual(data["savings_percent"], 56.5)
        self.assertEqual(
            data["top_saved"],
            [
                {"category": "run", "saved_bytes": 60},
                {"category": "git", "saved_bytes": 5},
            ],
        )
        self.assertEqual(
            data["top_calls"],
            [{"category": "git", "calls": 2}, {"category": "run", "calls": 1}],
        )
        self.assertEqual(data["top_strategies"], [])

    def test_total_text(self):
        self.seed([("git", 10, 5, 0, TS1), ("git", 5, 10, 0, TS1)])
        p = self.run_actx("gain")
        self.assertEqual(p.returncode, 0)
        self.assertIn("saved: 5 bytes", p.stdout)
        self.assertIn("~", p.stdout)
        self.assertIn("savings:", p.stdout)

    def test_mismatched_schema_treated_as_empty(self):
        os.environ["HOME"] = self.home.name
        try:
            conn = tracking.connect()
            conn.execute("DROP TABLE IF EXISTS calls")
            conn.execute("CREATE TABLE calls (id INTEGER)")
            conn.commit()
            conn.close()
        finally:
            del os.environ["HOME"]
        p = self.run_actx("gain", "--format", "json")
        self.assertEqual(p.returncode, 0)
        data = json.loads(p.stdout)
        self.assertEqual(data["total_saved_bytes"], 0)

    def test_empty_database_json(self):
        p = self.run_actx("gain", "--format", "json")
        self.assertEqual(p.returncode, 0)
        data = json.loads(p.stdout)
        self.assertEqual(data["total_saved_bytes"], 0)
        self.assertEqual(data["calls"], 0)

    def test_daily_json(self):
        self.seed(
            [
                ("git", 20, 10, 0, TS1),
                ("run", 50, 30, 0, TS2),
            ]
        )
        p = self.run_actx("gain", "--daily", "--format", "json")
        self.assertEqual(p.returncode, 0)
        data = json.loads(p.stdout)
        self.assertEqual(len(data["daily"]), 2)
        self.assertEqual(data["daily"][0]["saved_bytes"], 10)
        self.assertEqual(data["daily"][1]["saved_bytes"], 20)

    def test_history_has_categories_not_commands(self):
        self.seed([("git", 20, 10, 0, TS1), ("run", 50, 30, 0, TS2)])
        p = self.run_actx("gain", "--history")
        self.assertEqual(p.returncode, 0)
        self.assertIn("git", p.stdout)
        self.assertIn("run", p.stdout)
        self.assertNotIn("cmd git", p.stdout)

    def test_graph_text(self):
        self.seed([("git", 20, 10, 0, TS1)])
        p = self.run_actx("gain", "--graph")
        self.assertEqual(p.returncode, 0)
        self.assertTrue(p.stdout.strip())

    def test_breakdown(self):
        os.environ["HOME"] = self.home.name
        try:
            conn = tracking.connect()
            for strategy, cat, before, after, ts in [
                ("git.status", "git", 100, 40, TS1),
                ("git.diff", "git", 80, 30, TS1),
                ("ls", "ls", 30, 10, TS1),
            ]:
                command_hash = hashlib.sha1(("cmd %s" % cat).encode("utf-8")).hexdigest()
                conn.execute(
                    "INSERT INTO calls (command_hash, category, bytes_before, "
                    "bytes_after, exit_code, timestamp, passthrough, strategy) "
                    "VALUES (?, ?, ?, ?, 0, ?, 0, ?)",
                    (command_hash, cat, before, after, ts, strategy),
                )
            conn.commit()
            conn.close()
        finally:
            del os.environ["HOME"]
        p = self.run_actx("gain", "--breakdown", "--format", "json")
        self.assertEqual(p.returncode, 0)
        data = json.loads(p.stdout)
        self.assertEqual(len(data["breakdown"]), 3)
        self.assertEqual(data["breakdown"][0]["strategy"], "git.status")
        self.assertEqual(data["breakdown"][0]["saved_bytes"], 60)
        self.assertEqual(data["breakdown"][0]["percent"], 46.2)


if __name__ == "__main__":
    unittest.main()
