import hashlib
import json
import os
import stat
import sqlite3
import subprocess
import tempfile
import unittest

from actx_lib import tracking

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")

AUTH_HINT = "[actx] hint: auth error"
RATE_HINT = "[actx] hint: rate limit"


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


class SessionHintShimTests(unittest.TestCase):
    """TK-47: auth/rate-limit stderr hints on shim executables (G4, G5, G5b, G7).

    Shims live in a tmp PATH dir and print to stdout/stderr under a tmp HOME;
    actx runs them through the real CLI so each runner path is exercised E2E.
    """

    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.bin = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.bin.cleanup()
        self.home.cleanup()

    def install_shim(self, name, stdout="", stderr="", exit_code=1):
        path = os.path.join(self.bin.name, name)
        script = (
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "sys.stdout.write(%r)\n"
            "sys.stderr.write(%r)\n"
            "sys.exit(%d)\n" % (stdout, stderr, exit_code)
        )
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)

    def write_config(self):
        path = os.path.join(
            self.home.name, ".config", "actx", "config.json"
        )
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "tee": {"enabled": True, "mode": "always"},
                    "truncate": {"max_lines": 500, "max_line_chars": 300},
                },
                handle,
            )

    def run_actx(self, args):
        env = os.environ.copy()
        env["HOME"] = self.home.name
        env["PATH"] = self.bin.name + os.pathsep + env.get("PATH", "")
        return subprocess.run(
            [ACTX] + args, capture_output=True, text=True, env=env
        )

    def _tee_records(self):
        tee_dir = os.path.join(self.home.name, ".local", "share", "actx", "tee")
        records = []
        for name in os.listdir(tee_dir):
            with open(
                os.path.join(tee_dir, name), encoding="utf-8"
            ) as handle:
                records.append(handle.read())
        return records

    # G4: hint printed exactly once, original exit code, not in tee.
    def test_run_path_auth_hint_once_exit_kept_tee_clean(self):
        self.write_config()
        self.install_shim(
            "toolx", stdout="ok\n",
            stderr="ERROR: 401 Unauthorized — not logged in\n",
        )
        p = self.run_actx(["run", "toolx"])
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stderr.count("[actx] hint:"), 1)
        self.assertIn(AUTH_HINT, p.stderr)
        self.assertNotIn(RATE_HINT, p.stderr)
        for record in self._tee_records():
            self.assertNotIn("[actx] hint:", record)

    # G4 on a registry head: compacted_result path via `actx npm list`.
    def test_compacted_result_path_auth_hint_via_npm(self):
        self.install_shim(
            "npm", stdout="package\n",
            stderr="ERROR: 401 Unauthorized — not logged in\n",
        )
        p = self.run_actx(["npm", "list"])
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stderr.count("[actx] hint:"), 1)
        self.assertIn(AUTH_HINT, p.stderr)

    # G4 on a registry head: run_lossless path via `actx ls`.
    def test_run_lossless_path_auth_hint_via_ls(self):
        self.install_shim(
            "ls", stdout="file.txt\n",
            stderr="not logged in: run gh auth login\n",
        )
        p = self.run_actx(["ls"])
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stderr.count("[actx] hint:"), 1)
        self.assertIn(AUTH_HINT, p.stderr)

    # G5: exit 0 with a contextual pattern in the output — the exit-code
    # gate is the only thing suppressing the hint (bare "401" alone never
    # matches); compression stays intact.
    def test_exit_zero_with_401_no_hint(self):
        self.install_shim(
            "toolx", stdout="tested 401 responses\n",
            stderr="HTTP 401 Unauthorized scenario tested OK\n", exit_code=0,
        )
        p = self.run_actx(["run", "toolx"])
        self.assertEqual(p.returncode, 0)
        self.assertNotIn("[actx] hint:", p.stderr)
        self.assertIn("tested 401 responses", p.stdout)

    # G5b: bare numbers stay out of the patterns — a failing test's
    # `assert response.status_code == 429` output must not trigger a hint.
    def test_failing_assert_with_bare_429_no_hint(self):
        self.install_shim(
            "toolx", stdout="",
            stderr="FAILED test_x.py::test_y - assert response.status_code == 429\n",
        )
        p = self.run_actx(["run", "toolx"])
        self.assertEqual(p.returncode, 1)
        self.assertNotIn("[actx] hint:", p.stderr)

    # G7: contextual rate-limit forms print the rate hint exactly once.
    def test_rate_limit_hint_printed_once(self):
        self.install_shim(
            "toolx", stdout="",
            stderr="Rate limit exceeded, retry later\n",
        )
        p = self.run_actx(["run", "toolx"])
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stderr.count("[actx] hint:"), 1)
        self.assertIn(RATE_HINT, p.stderr)
        self.assertNotIn(AUTH_HINT, p.stderr)

    def test_both_hint_classes_at_most_two(self):
        self.install_shim(
            "toolx", stdout="",
            stderr="unauthorized and rate limit; HTTP 401; too many requests\n",
        )
        p = self.run_actx(["run", "toolx"])
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stderr.count("[actx] hint:"), 2)
        self.assertIn(AUTH_HINT, p.stderr)
        self.assertIn(RATE_HINT, p.stderr)

    # run_passthrough bytes mode: lossy decode of bytes stderr still matches.
    def test_raw_passthrough_bytes_stderr_auth_hint(self):
        self.install_shim(
            "toolx", stdout="ok\n", stderr="not logged in\n",
        )
        p = self.run_actx(["--raw", "run", "toolx"])
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stderr.count("[actx] hint:"), 1)
        self.assertIn(AUTH_HINT, p.stderr)


if __name__ == "__main__":
    unittest.main()
