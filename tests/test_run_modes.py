import io
import json
import os
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib import runner
from actx_lib.filters import test_runner_filter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")

CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}


class RunModeCliTests(unittest.TestCase):
    def run_actx(self, args, timeout=None):
        env = os.environ.copy()
        env["HOME"] = self.home.name
        return subprocess.run(
            [ACTX] + args, capture_output=True, text=True, env=env,
            timeout=timeout,
        )

    def write_config(self, extra):
        config = dict(CONFIG)
        config.update(extra)
        path = os.path.join(self.home.name, ".config", "actx", "config.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)

    def setUp(self):
        self.home = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.home.cleanup()

    def test_digest_prints_first_last_and_skipped(self):
        for _ in range(2):
            p = self.run_actx(["run", "--digest", "seq", "1", "1000"])
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("1\n2\n", p.stdout)
            self.assertIn("999\n1000", p.stdout)
            self.assertIn("lines skipped", p.stdout)

    def test_errors_prints_only_stderr(self):
        command = (
            "import sys; print('out'); print('err', file=sys.stderr)"
        )
        for _ in range(2):
            p = self.run_actx(["run", "--errors", "python3", "-c", command])
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout, "")
            self.assertIn("err", p.stderr)
            self.assertNotIn("out", p.stderr)

    def test_failures_unknown_runner_is_raw(self):
        p = self.run_actx(["run", "--failures", "python3", "-c", "print('hello')"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "hello\n")


class HangPolicyIntegrationTests(unittest.TestCase):
    """Never-wrap refusal, timeouts, stdin guard — every case bounded."""

    def setUp(self):
        self.home = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.home.cleanup()

    def run_actx(self, args):
        env = os.environ.copy()
        env["HOME"] = self.home.name
        return subprocess.run(
            [ACTX] + args, capture_output=True, text=True, env=env
        )

    def write_config(self, extra):
        config = dict(CONFIG)
        config.update(extra)
        path = os.path.join(self.home.name, ".config", "actx", "config.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)

    def test_tail_f_run_path_refused_before_start(self):
        self.write_config({"timeouts": {"default_s": 1, "generous_s": 1}})
        start = time.monotonic()
        p = self.run_actx(["run", "tail", "-f", "/dev/null"])
        elapsed = time.monotonic() - start
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertLess(elapsed, 2.0)
        self.assertIn("выполнить вручную", p.stderr)
        self.assertIn("tail -f /dev/null", p.stderr)

    def test_tail_f_head_path_refused_before_start(self):
        start = time.monotonic()
        p = self.run_actx(["tail", "-f", "/dev/null"])
        elapsed = time.monotonic() - start
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertLess(elapsed, 2.0)
        self.assertIn("выполнить вручную", p.stderr)

    def test_tail_f_passthrough_refused_before_start(self):
        start = time.monotonic()
        p = self.run_actx(["--raw", "tail", "-f", "/dev/null"])
        elapsed = time.monotonic() - start
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertLess(elapsed, 2.0)

    def test_default_timeout_returns_124(self):
        self.write_config({"timeouts": {"default_s": 1, "generous_s": 30}})
        start = time.monotonic()
        p = self.run_actx(["run", "sleep", "30"])
        elapsed = time.monotonic() - start
        self.assertEqual(p.returncode, 124, p.stderr)
        self.assertLess(elapsed, 3.0)
        self.assertIn("timed out", p.stderr)

    def test_generous_class_gets_generous_timeout(self):
        # No stdlib builder exists, so assert the class -> timeout mapping
        # directly: generous must not receive the short default timeout.
        captured = {}
        config = dict(CONFIG)
        config["timeouts"] = {"default_s": 1, "generous_s": 30}

        def fake_run(cmd, **kwargs):
            captured["timeout"] = kwargs.get("timeout")
            captured["stdin"] = kwargs.get("stdin")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with mock.patch("actx_lib.runner.subprocess.run", side_effect=fake_run):
            rc = runner.run(["flutter", "build", "apk"], config)
        self.assertEqual(rc, 0)
        self.assertEqual(captured["timeout"], 30)
        self.assertIs(captured["stdin"], subprocess.DEVNULL)

        captured.clear()
        with mock.patch("actx_lib.runner.subprocess.run", side_effect=fake_run):
            runner.run(["echo", "hi"], config)
        self.assertEqual(captured["timeout"], 1)

    def test_run_and_execute_pass_devnull_stdin(self):
        config = dict(CONFIG)

        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with mock.patch("actx_lib.runner.subprocess.run", side_effect=fake_run) as m:
            runner.run(["echo", "hi"], config)
            runner.run_passthrough(["echo", "hi"])
            runner.execute(["echo", "hi"])
        for call in m.call_args_list:
            self.assertIs(call.kwargs.get("stdin"), subprocess.DEVNULL)

    def test_timeout_seconds_fail_open_to_defaults(self):
        self.assertEqual(runner._timeout_seconds({}, "default"), 600)
        self.assertEqual(runner._timeout_seconds({}, "generous"), 1800)
        self.assertEqual(
            runner._timeout_seconds({"timeouts": {"default_s": "banana"}}, "default"),
            600,
        )
        self.assertEqual(
            runner._timeout_seconds({"timeouts": {"default_s": 0}}, "default"),
            600,
        )
        self.assertEqual(
            runner._timeout_seconds({"timeouts": {"default_s": -5}}, "default"),
            600,
        )
        self.assertEqual(
            runner._timeout_seconds({"timeouts": {"generous_s": 5}}, "generous"),
            5.0,
        )

    def test_timeout_on_errors_path_returns_124(self):
        self.write_config({"timeouts": {"default_s": 1, "generous_s": 30}})
        start = time.monotonic()
        p = self.run_actx(["run", "--errors", "sleep", "30"])
        elapsed = time.monotonic() - start
        self.assertEqual(p.returncode, 124, p.stderr)
        self.assertLess(elapsed, 3.0)
        self.assertIn("timed out", p.stderr)

    def test_never_wrap_on_errors_path_returns_125(self):
        start = time.monotonic()
        p = self.run_actx(["run", "--errors", "tail", "-f", "/dev/null"])
        elapsed = time.monotonic() - start
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertLess(elapsed, 2.0)
        self.assertIn("выполнить вручную", p.stderr)

    def test_stdin_guard_devnull(self):
        # Without the guard, `head -1` reading stdin would block; with
        # DEVNULL it sees EOF immediately.
        start = time.monotonic()
        p = self.run_actx(["run", "head", "-1"])
        elapsed = time.monotonic() - start
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertLess(elapsed, 5.0)

    def test_interactive_prompt_hint_after_run(self):
        script = "import sys; print('Proceed? [y/n]'); print('done')"
        p = self.run_actx(["run", "python3", "-c", script])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("интерактивная команда — выполнить вручную", p.stderr)
        # Command output itself is untouched.
        self.assertIn("Proceed? [y/n]", p.stdout)
        self.assertIn("done", p.stdout)

    def test_no_hint_without_prompt(self):
        p = self.run_actx(["run", "python3", "-c", "print('all good')"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("интерактивная команда", p.stderr)

    def test_invalid_timeout_config_falls_open_to_default(self):
        self.write_config({"timeouts": {"default_s": "banana"}})
        p = self.run_actx(["run", "echo", "ok"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("ok", p.stdout)


class DigestTextTests(unittest.TestCase):
    def test_small_text_is_unchanged(self):
        self.assertEqual(runner.digest_text("a\nb\n"), "a\nb\n")

    def test_large_text_gets_head_tail_and_skip_count(self):
        text = "\n".join(str(i) for i in range(1, 101)) + "\n"
        out = runner.digest_text(text, n=5)
        self.assertIn("1\n2\n3\n4\n5\n", out)
        self.assertIn("96\n97\n98\n99\n100", out)
        self.assertIn("90 lines skipped", out)


class KnownRunnerFailuresTests(unittest.TestCase):
    def test_known_runner_failures_only(self):
        stdout = (
            "============================= test session starts ==============================\n"
            "test_foo.py ..F..\n"
            "=================================== FAILURES ===================================\n"
            "_____________________________ test_name ______________________________________\n"
            "    def test_name():\n"
            ">       assert False\n"
            "E       assert False\n"
            "test_foo.py:5: AssertionError\n"
            "=========================== short test summary info ============================\n"
            "FAILED test_foo.py::test_name - assert False\n"
            "======================= 1 failed, 4 passed in 1.23s =========================\n"
        )
        result = subprocess.CompletedProcess(
            ["pytest"], 1, stdout, ""
        )
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch("actx_lib.runner.execute", return_value=result):
            with redirect_stdout(out), redirect_stderr(err):
                rc = test_runner_filter.run_failures(["pytest"], CONFIG)
        self.assertEqual(rc, 1)
        self.assertIn("test_name", out.getvalue())
        self.assertNotIn("1 failed, 4 passed", out.getvalue())


if __name__ == "__main__":
    unittest.main()
