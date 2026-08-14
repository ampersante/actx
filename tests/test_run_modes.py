import io
import os
import subprocess
import tempfile
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
    def run_actx(self, args):
        env = os.environ.copy()
        env["HOME"] = self.home.name
        return subprocess.run(
            [ACTX] + args, capture_output=True, text=True, env=env
        )

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
