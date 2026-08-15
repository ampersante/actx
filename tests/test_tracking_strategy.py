import os
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


class TrackingStrategyTests(unittest.TestCase):
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

    def db_path(self):
        return os.path.join(self.home.name, ".local", "share", "actx", "history.db")

    def strategies(self):
        conn = sqlite3.connect(self.db_path())
        rows = [row[0] for row in conn.execute("SELECT strategy FROM calls")]
        conn.close()
        return rows

    def test_git_status_records_strategy(self):
        subprocess.run(["git", "init"], cwd=self.work.name, check=True, capture_output=True)
        subprocess.run(
            ["git", "config", "user.email", "a@example.com"],
            cwd=self.work.name, check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "a"],
            cwd=self.work.name, check=True, capture_output=True,
        )
        p = self.run_actx("git", "status")
        self.assertEqual(p.returncode, 0)
        self.assertIn("git.status", self.strategies())

    def test_ls_records_strategy(self):
        p = self.run_actx("ls")
        self.assertEqual(p.returncode, 0)
        self.assertIn("ls", self.strategies())

    def test_passthrough_records_passthrough(self):
        subprocess.run(["git", "init"], cwd=self.work.name, check=True, capture_output=True)
        p = self.run_actx("git", "status", "--porcelain")
        self.assertEqual(p.returncode, 0)
        self.assertIn("passthrough", self.strategies())


if __name__ == "__main__":
    unittest.main()
