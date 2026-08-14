import io
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib.filters import linter_filter

CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}

RUFF = """\
src/main.py:3:1: F401 `os` imported but unused
src/main.py:5:1: E501 Line too long (89 > 88)
Found 2 errors.
"""

TSC = """\
src/foo.ts(3,5): error TS2304: Cannot find name 'console'.
src/bar.ts(10,1): error TS2322: Type 'string' is not assignable to type 'number'.
"""

ESLINT = """\
/path/src/foo.js
  3:1  error  Unexpected console statement  no-console
  5:2  warning  Something  no-warn

\u2716 2 problems (1 error, 1 warning)
"""

GOLANGCI = """\
pkg/foo.go:10:3: S1021: should merge variable declaration (gosimple)
pkg/bar.go:20:5: revive: exported function Foo should have comment
"""

CARGO_BUILD = """\
   Compiling foo v0.1.0
error[E0425]: cannot find value `x` in this scope
 --> src/main.rs:3:5
  |
3 |     let y = x;
  |             ^
error: could not compile `foo` due to 1 previous error
"""

CARGO_CLIPPY = """\
    Checking foo v0.1.0
warning: this if statement can be collapsed
 --> src/main.rs:2:5
  |
2 | if x { }
  | ^^^^^^^^^
  |
  = help: for further information visit https://rustc.dev
"""

NEXT = """\
   \u25b2 Next.js 14.2.3
   Creating an optimized production build ...
 \u2713 Compiled successfully
   Linting and checking validity of types ...
Failed to compile.

./src/app/page.tsx:10:5
Type error: Type 'string' is not assignable to type 'number'.

  3 | const x: number = 'a';
    |                     ^

> Build failed because of webpack errors
"""


class LinterParserTests(unittest.TestCase):
    def test_ruff_keeps_errors(self):
        out = linter_filter.compact_ruff(RUFF)
        self.assertIn("F401", out)
        self.assertIn("E501", out)
        self.assertIn("2 errors", out)
        self.assertNotIn("Found 2 errors.", out)

    def test_tsc_keeps_errors(self):
        out = linter_filter.compact_tsc(TSC)
        self.assertIn("TS2304", out)
        self.assertIn("TS2322", out)
        self.assertIn("2 errors", out)

    def test_eslint_drops_warnings_and_summary(self):
        out = linter_filter.compact_eslint(ESLINT)
        self.assertIn("/path/src/foo.js", out)
        self.assertIn("no-console", out)
        self.assertIn("1 errors", out)
        self.assertNotIn("warning", out)
        self.assertNotIn("2 problems", out)

    def test_golangci_lint_keeps_errors(self):
        out = linter_filter.compact_golangci_lint(GOLANGCI)
        self.assertIn("S1021", out)
        self.assertIn("revive", out)
        self.assertIn("2 errors", out)

    def test_cargo_build_keeps_errors(self):
        out = linter_filter.compact_cargo(CARGO_BUILD)
        self.assertIn("E0425", out)
        self.assertIn("src/main.rs", out)
        self.assertIn("1 errors", out)
        self.assertNotIn("Compiling", out)

    def test_cargo_clippy_drops_warnings(self):
        out = linter_filter.compact_cargo(CARGO_CLIPPY)
        self.assertEqual(out, "0 errors")

    def test_next_build_keeps_errors(self):
        out = linter_filter.compact_next(NEXT)
        self.assertIn("Failed to compile.", out)
        self.assertIn("./src/app/page.tsx", out)
        self.assertIn("Type error", out)
        self.assertIn("> Build failed", out)
        self.assertNotIn("Next.js", out)
        self.assertNotIn("Creating", out)


class LinterExitCodeTests(unittest.TestCase):
    def test_ruff_preserves_exit_code(self):
        result = subprocess.CompletedProcess(["ruff", "."], 1, RUFF, "")
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch("actx_lib.runner.execute", return_value=result):
            with redirect_stdout(out), redirect_stderr(err):
                rc = linter_filter.run_ruff([], CONFIG)
        self.assertEqual(rc, 1)
        self.assertIn("F401", out.getvalue())


def _fail_open(run_fn, args, patch_target):
    result = subprocess.CompletedProcess(
        args, 0, "raw stdout\n", "raw stderr\n"
    )
    out = io.StringIO()
    err = io.StringIO()
    raiser = mock.Mock(side_effect=RuntimeError("boom"))
    with mock.patch("actx_lib.runner.execute", return_value=result), mock.patch(
        patch_target, side_effect=raiser
    ):
        with redirect_stdout(out), redirect_stderr(err):
            rc = run_fn(args, CONFIG)
    return rc, out.getvalue(), err.getvalue()


class LinterFailOpenTests(unittest.TestCase):
    def _assert_raw(self, rc, out, err):
        self.assertEqual(rc, 0)
        self.assertEqual(out, "raw stdout\n")
        self.assertEqual(err, "raw stderr\n")

    def test_ruff_fails_open(self):
        rc, out, err = _fail_open(
            linter_filter.run_ruff,
            [],
            "actx_lib.filters.linter_filter.compact_ruff",
        )
        self._assert_raw(rc, out, err)

    def test_tsc_fails_open(self):
        rc, out, err = _fail_open(
            linter_filter.run_tsc,
            [],
            "actx_lib.filters.linter_filter.compact_tsc",
        )
        self._assert_raw(rc, out, err)

    def test_eslint_fails_open(self):
        rc, out, err = _fail_open(
            linter_filter.run_eslint,
            [],
            "actx_lib.filters.linter_filter.compact_eslint",
        )
        self._assert_raw(rc, out, err)

    def test_golangci_lint_fails_open(self):
        rc, out, err = _fail_open(
            linter_filter.run_golangci_lint,
            [],
            "actx_lib.filters.linter_filter.compact_golangci_lint",
        )
        self._assert_raw(rc, out, err)

    def test_cargo_build_fails_open(self):
        rc, out, err = _fail_open(
            linter_filter.run_cargo,
            ["build"],
            "actx_lib.filters.linter_filter.compact_cargo",
        )
        self._assert_raw(rc, out, err)

    def test_cargo_clippy_fails_open(self):
        rc, out, err = _fail_open(
            linter_filter.run_cargo,
            ["clippy"],
            "actx_lib.filters.linter_filter.compact_cargo",
        )
        self._assert_raw(rc, out, err)

    def test_next_fails_open(self):
        rc, out, err = _fail_open(
            linter_filter.run_next,
            ["build"],
            "actx_lib.filters.linter_filter.compact_next",
        )
        self._assert_raw(rc, out, err)


if __name__ == "__main__":
    unittest.main()
