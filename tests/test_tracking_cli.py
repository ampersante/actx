import json
import os
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


class TrackingCliTests(unittest.TestCase):
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

    def config_path(self):
        return os.path.join(self.home.name, ".config", "actx", "config.json")

    def db_path(self):
        return os.path.join(self.home.name, ".local", "share", "actx", "history.db")

    def read_config(self):
        with open(self.config_path(), encoding="utf-8") as handle:
            return json.load(handle)

    def test_off_writes_disabled(self):
        p = self.run_actx("tracking", "off")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self.read_config()["tracking"]["enabled"], False)

    def test_on_writes_enabled(self):
        self.run_actx("tracking", "off")
        p = self.run_actx("tracking", "on")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(self.read_config()["tracking"]["enabled"], True)

    def test_status_prints_state(self):
        p = self.run_actx("tracking", "status")
        self.assertEqual(p.returncode, 0)
        self.assertIn("tracking:", p.stdout)
        self.assertIn("history.db:", p.stdout)

    def test_clear_removes_db(self):
        self.run_actx("run", "python3", "-c", "print(1)")
        self.assertTrue(os.path.exists(self.db_path()))
        p = self.run_actx("tracking", "clear")
        self.assertEqual(p.returncode, 0)
        self.assertFalse(os.path.exists(self.db_path()))

    def test_off_stops_run_and_raw(self):
        self.run_actx("tracking", "off")
        p = self.run_actx("run", "python3", "-c", "print(1)")
        self.assertEqual(p.returncode, 0)
        p = self.run_actx("--raw", "python3", "-c", "print(1)")
        self.assertEqual(p.returncode, 0)
        self.assertFalse(os.path.exists(self.db_path()))

    def test_off_stops_bypass_path(self):
        path = self.config_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"tracking": {"enabled": False}, "bypass_commands": ["python3"]}, handle)
        p = self.run_actx("run", "python3", "-c", "print(1)")
        self.assertEqual(p.returncode, 0)
        self.assertFalse(os.path.exists(self.db_path()))


if __name__ == "__main__":
    unittest.main()
