import io
import os
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib.filters import mobile_filter

CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}

FIXTURES = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "mobile"
)


def _fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return handle.read()


FLUTTER_TEST_FAIL = _fixture("flutter_test_fail.in.txt")
FLUTTER_ANALYZE = _fixture("flutter_analyze_issues.in.txt")
XCODEBUILD_FAILED = _fixture("xcodebuild_failed.in.txt")
SWIFT_BUILD = (
    "Building for debugging...\n"
    "error: /Users/dev/Projects/Tool/Sources/main.swift:3:8: error: no such module 'Foo'\n"
    "import Foo\n"
    "       ^\n"
    "error: fatalError\n"
)


def _run_with_stdout(run_fn, args, stdout, returncode):
    result = subprocess.CompletedProcess(["x"] + args, returncode, stdout, "")
    out = io.StringIO()
    err = io.StringIO()
    with mock.patch("actx_lib.runner.execute", return_value=result):
        with redirect_stdout(out), redirect_stderr(err):
            rc = run_fn(args, CONFIG)
    return rc, out.getvalue(), err.getvalue()


class MobileCompactionTests(unittest.TestCase):
    def test_flutter_test_failure_compacted(self):
        rc, out, _err = _run_with_stdout(
            mobile_filter.run_flutter, ["test"], FLUTTER_TEST_FAIL, 1
        )
        self.assertEqual(rc, 1)
        self.assertIn("counter value should be decremented [E]", out)
        self.assertIn("Expected: <-1>", out)
        self.assertIn("2 failed, 4 passed", out)
        self.assertNotIn("loading test/widget_test.dart", out)
        self.assertNotIn("counter value starts at zero", out)

    def test_flutter_test_passing_output_is_counter_only(self):
        rc, out, _err = _run_with_stdout(
            mobile_filter.run_flutter,
            ["test"],
            _fixture("flutter_test_pass.in.txt"),
            0,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "0 failed, 3 passed\n")

    def test_flutter_analyze_keeps_diagnostics(self):
        rc, out, _err = _run_with_stdout(
            mobile_filter.run_flutter, ["analyze"], FLUTTER_ANALYZE, 1
        )
        self.assertEqual(rc, 1)
        self.assertIn("error • 'fetchUserr' isn't defined", out)
        self.assertIn("warning • Unused import: 'dart:math'", out)
        self.assertIn("info • Prefer const with constant constructors", out)
        self.assertIn("3 issues", out)
        self.assertNotIn("Analyzing", out)

    def test_dart_analyze_keeps_diagnostics(self):
        rc, out, _err = _run_with_stdout(
            mobile_filter.run_dart,
            ["analyze"],
            _fixture("dart_analyze_issues.in.txt"),
            1,
        )
        self.assertEqual(rc, 1)
        self.assertIn(
            "error • Argument type 'int' can't be assigned", out
        )
        self.assertIn("3 issues", out)

    def test_swiftlint_violations_kept(self):
        rc, out, _err = _run_with_stdout(
            mobile_filter.run_swiftlint,
            ["lint"],
            _fixture("swiftlint_violations.in.txt"),
            2,
        )
        self.assertEqual(rc, 2)
        self.assertIn("Force Unwrap Violation", out)
        self.assertIn("3 violations", out)
        self.assertNotIn("Linting Swift files", out)

    def test_xcodebuild_build_failure_keeps_errors_and_exit_code(self):
        # Red gate: build errors must survive compaction verbatim.
        rc, out, _err = _run_with_stdout(
            mobile_filter.run_xcodebuild,
            ["-scheme", "App", "-destination", "platform=iOS Simulator", "build"],
            XCODEBUILD_FAILED,
            65,
        )
        self.assertEqual(rc, 65)
        self.assertIn("error: cannot find 'fetchUserr' in scope", out)
        self.assertIn("** BUILD FAILED ** (2 errors)", out)
        self.assertNotIn("CompileSwift normal arm64", out)
        self.assertNotIn("ComputeTargetIntegrity", out)

    def test_swift_build_keeps_swiftc_errors(self):
        rc, out, _err = _run_with_stdout(
            mobile_filter.run_swift, ["build"], SWIFT_BUILD, 1
        )
        self.assertEqual(rc, 1)
        self.assertIn("error: no such module 'Foo'", out)
        self.assertNotIn("Building for debugging", out)

    def test_empty_stdout_falls_back_to_raw(self):
        # stdout_compactor returns None for empty stdout -> raw passthrough
        # inside compacted_result; stderr still printed.
        result = subprocess.CompletedProcess(
            ["flutter", "test"], 0, "", "some stderr\n"
        )
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch("actx_lib.runner.execute", return_value=result):
            with redirect_stdout(out), redirect_stderr(err):
                rc = mobile_filter.run_flutter(["test"], CONFIG)
        self.assertEqual(rc, 0)
        self.assertEqual(err.getvalue(), "some stderr\n")


class MobileRoutingTests(unittest.TestCase):
    """Subcommands without a compaction profile route to raw passthrough;
    informational RO output routes to generic lossless compaction."""

    def _assert_passthrough(self, run_fn, args, cmd):
        sentinel = 42
        with mock.patch(
            "actx_lib.runner.run_passthrough", return_value=sentinel
        ) as passthrough:
            self.assertEqual(run_fn(args, CONFIG), sentinel)
        passthrough.assert_called_once_with(cmd)

    def _assert_lossless(self, run_fn, args, cmd):
        sentinel = 7
        with mock.patch(
            "actx_lib.runner.run_lossless", return_value=sentinel
        ) as lossless:
            self.assertEqual(run_fn(args, CONFIG), sentinel)
        lossless.assert_called_once()

    def test_flutter_pub_get_passthrough(self):
        self._assert_passthrough(
            mobile_filter.run_flutter, ["pub", "get"], ["flutter", "pub", "get"]
        )

    def test_flutter_run_passthrough(self):
        self._assert_passthrough(
            mobile_filter.run_flutter, ["run"], ["flutter", "run"]
        )

    def test_flutter_doctor_lossless(self):
        self._assert_lossless(
            mobile_filter.run_flutter, ["doctor"], ["flutter", "doctor"]
        )

    def test_flutter_pub_outdated_lossless(self):
        self._assert_lossless(
            mobile_filter.run_flutter,
            ["pub", "outdated"],
            ["flutter", "pub", "outdated"],
        )

    def test_flutter_pub_deps_lossless(self):
        self._assert_lossless(
            mobile_filter.run_flutter, ["pub", "deps"], ["flutter", "pub", "deps"]
        )

    def test_dart_unknown_sub_passthrough(self):
        self._assert_passthrough(
            mobile_filter.run_dart, ["run", "x"], ["dart", "run", "x"]
        )

    def test_swift_test_lossless(self):
        self._assert_lossless(
            mobile_filter.run_swift, ["test"], ["swift", "test"]
        )

    def test_swift_package_passthrough(self):
        self._assert_passthrough(
            mobile_filter.run_swift,
            ["package", "resolve"],
            ["swift", "package", "resolve"],
        )

    def test_swiftlint_autocorrect_passthrough(self):
        self._assert_passthrough(
            mobile_filter.run_swiftlint,
            ["autocorrect"],
            ["swiftlint", "autocorrect"],
        )

    def test_swiftformat_bare_passthrough(self):
        self._assert_passthrough(
            mobile_filter.run_swiftformat, [], ["swiftformat"]
        )

    def test_swiftformat_lint_lossless(self):
        self._assert_lossless(
            mobile_filter.run_swiftformat, ["--lint", "."], ["swiftformat", "--lint", "."]
        )

    def test_swiftformat_dry_run_lossless(self):
        self._assert_lossless(
            mobile_filter.run_swiftformat,
            ["--dry-run", "Sources"],
            ["swiftformat", "--dry-run", "Sources"],
        )

    def test_xcodebuild_bare_passthrough(self):
        self._assert_passthrough(mobile_filter.run_xcodebuild, [], ["xcodebuild"])

    def test_xcodebuild_list_lossless(self):
        self._assert_lossless(
            mobile_filter.run_xcodebuild, ["-list"], ["xcodebuild", "-list"]
        )

    def test_xcodebuild_showsdks_lossless(self):
        self._assert_lossless(
            mobile_filter.run_xcodebuild,
            ["-showsdks"],
            ["xcodebuild", "-showsdks"],
        )

    def test_xcodebuild_show_build_settings_lossless(self):
        self._assert_lossless(
            mobile_filter.run_xcodebuild,
            ["-project", "App.xcodeproj", "-showBuildSettings"],
            ["xcodebuild", "-project", "App.xcodeproj", "-showBuildSettings"],
        )

    def test_xcrun_simctl_list_lossless(self):
        self._assert_lossless(
            mobile_filter.run_xcrun,
            ["simctl", "list", "devices"],
            ["xcrun", "simctl", "list", "devices"],
        )

    def test_xcrun_simctl_boot_passthrough(self):
        self._assert_passthrough(
            mobile_filter.run_xcrun,
            ["simctl", "boot", "x"],
            ["xcrun", "simctl", "boot", "x"],
        )

    def test_xcrun_plain_passthrough(self):
        self._assert_passthrough(
            mobile_filter.run_xcrun, ["--find", "swift"], ["xcrun", "--find", "swift"]
        )

    def test_pod_install_passthrough(self):
        self._assert_passthrough(
            mobile_filter.run_pod, ["install"], ["pod", "install"]
        )

    def test_pod_outdated_lossless(self):
        self._assert_lossless(
            mobile_filter.run_pod, ["outdated"], ["pod", "outdated"]
        )

    def test_pod_list_lossless(self):
        self._assert_lossless(mobile_filter.run_pod, ["list"], ["pod", "list"])

    def test_gradlew_lossless(self):
        self._assert_lossless(
            mobile_filter.run_gradlew, ["build"], ["./gradlew", "build"]
        )


class MobileFailOpenTests(unittest.TestCase):
    def _assert_raw(self, rc, out, err, expected_rc):
        self.assertEqual(rc, expected_rc)
        self.assertEqual(out, "raw stdout\n")
        self.assertEqual(err, "raw stderr\n")

    def test_flutter_test_engine_exception_fails_open(self):
        # RK-03: an exception inside the compact_profiles engine must reach
        # the raw passthrough with the original exit code, not the caller.
        result = subprocess.CompletedProcess(
            ["flutter", "test"], 1, "raw stdout\n", "raw stderr\n"
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
                rc = mobile_filter.run_flutter(["test"], CONFIG)
        self._assert_raw(rc, out.getvalue(), err.getvalue(), 1)

    def test_flutter_analyze_engine_exception_fails_open(self):
        result = subprocess.CompletedProcess(
            ["flutter", "analyze"], 3, "raw stdout\n", "raw stderr\n"
        )
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch(
            "actx_lib.runner.execute", return_value=result
        ), mock.patch(
            "actx_lib.filters.compact_profiles.parse_lint",
            side_effect=RuntimeError("boom"),
        ):
            with redirect_stdout(out), redirect_stderr(err):
                rc = mobile_filter.run_flutter(["analyze"], CONFIG)
        self._assert_raw(rc, out.getvalue(), err.getvalue(), 3)

    def test_xcodebuild_engine_exception_fails_open(self):
        result = subprocess.CompletedProcess(
            ["xcodebuild", "-scheme", "App", "build"],
            65,
            "raw stdout\n",
            "raw stderr\n",
        )
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch(
            "actx_lib.runner.execute", return_value=result
        ), mock.patch(
            "actx_lib.filters.compact_profiles.parse_lint",
            side_effect=RuntimeError("boom"),
        ):
            with redirect_stdout(out), redirect_stderr(err):
                rc = mobile_filter.run_xcodebuild(
                    ["-scheme", "App", "build"], CONFIG
                )
        self._assert_raw(rc, out.getvalue(), err.getvalue(), 65)

    def test_execute_oserror_returns_1(self):
        for run_fn, args in (
            (mobile_filter.run_flutter, ["test"]),
            (mobile_filter.run_swiftlint, ["lint"]),
            (mobile_filter.run_xcodebuild, ["-scheme", "App", "build"]),
        ):
            with self.subTest(run_fn=run_fn.__name__):
                with mock.patch("actx_lib.runner.execute", return_value=None):
                    self.assertEqual(run_fn(args, CONFIG), 1)


if __name__ == "__main__":
    unittest.main()
