import hashlib
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest

from actx_lib import tracking

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


class RunnerCliTests(unittest.TestCase):
    def run_actx(self, args, home):
        env = os.environ.copy()
        env["HOME"] = home
        return subprocess.run(
            [ACTX] + args,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_run_false_creates_tee_file_with_exit_code_1(self):
        with tempfile.TemporaryDirectory() as home:
            p = self.run_actx(["run", "false"], home)
            self.assertEqual(p.returncode, 1)
            tee_dir = os.path.join(home, ".local", "share", "actx", "tee")
            files = os.listdir(tee_dir)
            self.assertEqual(len(files), 1)
            with open(os.path.join(tee_dir, files[0]), encoding="utf-8") as handle:
                record = json.load(handle)
            self.assertEqual(record["exit_code"], 1)

    def test_git_status_outside_repo_exits_128(self):
        with tempfile.TemporaryDirectory() as home:
            with tempfile.TemporaryDirectory() as workdir:
                p = subprocess.run(
                    [ACTX, "git", "status"],
                    capture_output=True,
                    text=True,
                    cwd=workdir,
                    env={**os.environ, "HOME": home},
                )
                self.assertEqual(p.returncode, 128)

    def test_tee_file_never_contains_secret_lines(self):
        # E2E over the actx process: _write_tee masks every caller's streams,
        # so a secret line must not reach the tee file in any path.
        with tempfile.TemporaryDirectory() as home:
            config_path = os.path.join(home, ".config", "actx", "config.json")
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "tee": {"enabled": True, "mode": "always"},
                        "truncate": {"max_lines": 500, "max_line_chars": 300},
                    },
                    handle,
                )
            p = self.run_actx(
                ["run", "python3", "-c",
                 "print('API_KEY=sk-e2e-secret'); print('plain line')"],
                home,
            )
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertNotIn("API_KEY", p.stdout)
            tee_dir = os.path.join(home, ".local", "share", "actx", "tee")
            files = os.listdir(tee_dir)
            self.assertEqual(len(files), 1)
            with open(os.path.join(tee_dir, files[0]), encoding="utf-8") as handle:
                record = handle.read()
            self.assertNotIn("API_KEY", record)
            self.assertIn("plain line", record)


class RecordStoreTextTests(unittest.TestCase):
    def test_store_text_false_writes_empty_command_text(self):
        home = tempfile.TemporaryDirectory()
        os.environ["HOME"] = home.name
        try:
            tracking.record(["echo", "s3cret-token"], "echo", 10, 5, 0, store_text=False)
        finally:
            del os.environ["HOME"]
        conn = sqlite3.connect(
            os.path.join(home.name, ".local", "share", "actx", "history.db")
        )
        try:
            rows = list(conn.execute("SELECT command_text, command_hash FROM calls"))
        finally:
            conn.close()
        home.cleanup()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "")
        self.assertEqual(
            rows[0][1],
            hashlib.sha1(b"echo s3cret-token").hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
