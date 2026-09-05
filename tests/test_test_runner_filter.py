import io
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib.filters import test_runner_filter

CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}

PYTEST = """\
============================= test session starts ==============================
platform darwin -- Python 3.14.2, pytest-8.3.5
collected 25 items

test_foo.py ..F.. [ 20%]
test_bar.py F.... [ 80%]
test_baz.py ..... [100%]

=================================== FAILURES ===================================
_____________________________ test_name ______________________________________

    def test_name():
>       assert False
E       assert False

test_foo.py:5: AssertionError
_____________________________ test_other ______________________________________

    def test_other():
>       assert 1 == 2
E       assert 1 == 2

test_bar.py:8: AssertionError
=========================== short test summary info ============================
FAILED test_foo.py::test_name - assert False
FAILED test_bar.py::test_other - assert 1 == 2
======================= 2 failed, 23 passed in 1.23s =========================
"""

CARGO = """\
   Compiling foo v0.1.0
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.5s
     Running unittests src/lib.rs (target/debug/deps/foo-abc)

running 5 tests
test tests::test_pass ... ok
test tests::test_fail ... FAILED
test tests::test_another_pass ... ok
test tests::test_third_pass ... ok
test tests::test_fourth_pass ... ok

failures:

---- tests::test_fail stdout ----
thread 'tests::test_fail' panicked at src/lib.rs:10:5:
assertion `left == right` failed
  left: 1
 right: 2


failures:
    tests::test_fail

test result: FAILED. 4 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
"""

GO = """\
=== RUN   TestFoo
--- PASS: TestFoo (0.00s)
=== RUN   TestBar
--- FAIL: TestBar (0.00s)
    foo_test.go:12: expected 1, got 2
=== RUN   TestBaz
--- PASS: TestBaz (0.00s)
FAIL
FAIL    example.com/foo  0.123s
FAIL
"""

JEST = """\
PASS src/foo.test.js
  \u2713 adds two numbers (5 ms)
FAIL src/bar.test.js
  \u25cf adds wrong numbers

    expect(received).toBe(expected)

    Expected: 2
    Received: 3

      10 | test('adds wrong numbers', () => {
      11 |   expect(add(1, 1)).toBe(2);
    > 12 |   expect(1 + 1).toBe(3);
         |                 ^
      13 | });

  \u25cf another wrong number

    Expected: 4
    Received: 5

Test Suites: 1 failed, 1 passed, 2 total
Tests:       2 failed, 1 passed, 3 total
Snapshots:   0 total
Time:        1.2 s
"""

VITEST = """\
 \u2713 src/foo.test.ts (1 test) 5ms
 \u276f src/bar.test.ts (2 tests) 7ms
   \u00d7 adds wrong numbers 3ms
     \u2192 expected 2 to be 3
   \u00d7 another wrong number 4ms
     \u2192 expected 4 to be 5

 Test Files  1 failed | 1 passed (2)
      Tests  2 failed | 1 passed (3)
"""


class TestRunnerParserTests(unittest.TestCase):
    def test_pytest_keeps_failures_and_counter(self):
        out = test_runner_filter.compact(PYTEST, "pytest")
        self.assertIn("test_name", out)
        self.assertIn("test_other", out)
        self.assertIn("2 failed, 23 passed", out)
        self.assertIn("test_foo.py:", out)
        self.assertIn("test_bar.py:", out)
        self.assertNotIn("test session starts", out)
        self.assertNotIn("[100%]", out)

    def test_cargo_test_keeps_failures_and_counter(self):
        out = test_runner_filter.compact(CARGO, "cargo")
        self.assertIn("tests::test_fail", out)
        self.assertIn("1 failed, 4 passed", out)
        self.assertNotIn("Compiling", out)
        self.assertNotIn("running 5 tests", out)
        self.assertNotIn("... ok", out)

    def test_go_test_keeps_failures_and_counter(self):
        out = test_runner_filter.compact(GO, "go")
        self.assertIn("--- FAIL: TestBar", out)
        self.assertIn("foo_test.go:12", out)
        self.assertIn("1 failed, 2 passed", out)
        self.assertNotIn("--- PASS", out)
        self.assertNotIn("=== RUN", out)

    def test_jest_keeps_failures_and_counter(self):
        out = test_runner_filter.compact(JEST, "jest")
        self.assertIn("FAIL src/bar.test.js", out)
        self.assertIn("adds wrong numbers", out)
        self.assertIn("2 failed, 1 passed", out)
        self.assertNotIn("PASS src/foo.test.js", out)
        self.assertNotIn("adds two numbers", out)

    def test_vitest_keeps_failures_and_counter(self):
        out = test_runner_filter.compact(VITEST, "vitest")
        self.assertIn("src/bar.test.ts", out)
        self.assertIn("adds wrong numbers", out)
        self.assertIn("2 failed, 1 passed", out)
        self.assertNotIn("src/foo.test.ts", out)

    def test_detect_known_runners(self):
        self.assertEqual(test_runner_filter.detect(["pytest"]), "pytest")
        self.assertEqual(
            test_runner_filter.detect(["cargo", "test"]), "cargo"
        )
        self.assertEqual(test_runner_filter.detect(["go", "test"]), "go")
        self.assertEqual(test_runner_filter.detect(["jest"]), "jest")
        self.assertEqual(test_runner_filter.detect(["vitest"]), "vitest")

    def test_detect_unknown_runner(self):
        self.assertIsNone(test_runner_filter.detect(["python3", "-c", "x"]))


def _fail_open(run_fn, args, tool):
    result = subprocess.CompletedProcess(
        args, 0, "raw stdout\n", "raw stderr\n"
    )
    out = io.StringIO()
    err = io.StringIO()
    raiser = mock.Mock(side_effect=RuntimeError("boom"))
    with mock.patch("actx_lib.runner.execute", return_value=result), mock.patch.dict(
        test_runner_filter.TOOL_PARSERS, {tool: raiser}
    ):
        with redirect_stdout(out), redirect_stderr(err):
            rc = run_fn(args, CONFIG)
    return rc, out.getvalue(), err.getvalue()


class TestRunnerFailOpenTests(unittest.TestCase):
    def test_pytest_fails_open(self):
        rc, out, err = _fail_open(
            test_runner_filter.run_pytest, [], "pytest"
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "raw stdout\n")
        self.assertEqual(err, "raw stderr\n")

    def test_cargo_test_fails_open(self):
        rc, out, err = _fail_open(
            test_runner_filter.run_cargo_test, ["test"], "cargo"
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "raw stdout\n")
        self.assertEqual(err, "raw stderr\n")

    def test_go_test_fails_open(self):
        rc, out, err = _fail_open(
            test_runner_filter.run_go_test, ["test"], "go"
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "raw stdout\n")
        self.assertEqual(err, "raw stderr\n")

    def test_jest_fails_open(self):
        rc, out, err = _fail_open(test_runner_filter.run_jest, [], "jest")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "raw stdout\n")
        self.assertEqual(err, "raw stderr\n")

    def test_vitest_fails_open(self):
        rc, out, err = _fail_open(
            test_runner_filter.run_vitest, [], "vitest"
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "raw stdout\n")
        self.assertEqual(err, "raw stderr\n")

    def test_profile_engine_exception_fails_open(self):
        # RK-03: an exception inside the compact_profiles engine must reach
        # the raw passthrough with the original exit code, not the caller.
        result = subprocess.CompletedProcess(
            ["pytest"], 0, "raw stdout\n", "raw stderr\n"
        )
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch(
            "actx_lib.runner.execute", return_value=result
        ), mock.patch(
            "actx_lib.filters.compact_profiles.parse_test",
            side_effect=RuntimeError("boom"),
        ):
            with redirect_stdout(out), redirect_stderr(err):
                rc = test_runner_filter.run_pytest([], CONFIG)
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), "raw stdout\n")
        self.assertEqual(err.getvalue(), "raw stderr\n")


if __name__ == "__main__":
    unittest.main()
