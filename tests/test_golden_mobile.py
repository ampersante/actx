"""Golden byte-for-byte baseline for the mobile toolchain compactors (TK-42).

Each pair tests/fixtures/mobile/<name>.in.txt + <name>.out.txt is a realistic
flutter/dart/swiftlint/xcodebuild dump (documentation formats); the profile
compactor must reproduce the dump byte-for-byte. Red gate: a build-failure
fixture must keep its error messages verbatim in the compacted output.
"""

import os
import unittest

from actx_lib.filters import compact_profiles, mobile_filter

GOLDEN_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "mobile"
)


def _test_runner_compact(profile_name):
    def compact(text):
        return mobile_filter._test_compact(text, profile_name)

    return compact


def _linter_compact(profile_name):
    def compact(text):
        return compact_profiles.parse_lint(
            text, compact_profiles.PROFILES[profile_name]
        )

    return compact


# case prefix -> compactor under test
CASES = {
    "flutter_test": _test_runner_compact("flutter_test"),
    "dart_test": _test_runner_compact("dart_test"),
    "flutter_analyze": _linter_compact("flutter_analyze"),
    "dart_analyze": _linter_compact("dart_analyze"),
    "swiftlint": _linter_compact("swiftlint"),
    "xcodebuild": _linter_compact("xcodebuild"),
}


def _case_for(name):
    for prefix in sorted(CASES, key=len, reverse=True):
        if name.startswith(prefix + "_"):
            return prefix
    raise AssertionError("golden dump %r matches no compactor case" % name)


class GoldenMobileCompactorTests(unittest.TestCase):
    def test_all_dumps_match_byte_for_byte(self):
        names = sorted(
            n[: -len(".in.txt")]
            for n in os.listdir(GOLDEN_DIR)
            if n.endswith(".in.txt")
        )
        self.assertTrue(names)
        for name in names:
            with self.subTest(case=name):
                in_path = os.path.join(GOLDEN_DIR, name + ".in.txt")
                out_path = os.path.join(GOLDEN_DIR, name + ".out.txt")
                with open(in_path, "rb") as handle:
                    text = handle.read().decode("utf-8")
                with open(out_path, "rb") as handle:
                    expected = handle.read()
                got = CASES[_case_for(name)](text)
                self.assertEqual(
                    got.encode("utf-8"),
                    expected,
                    "output of %r differs from golden dump %s"
                    % (_case_for(name), out_path),
                )

    def test_pass_and_fail_fixtures_exist_per_profile(self):
        names = {
            n[: -len(".in.txt")]
            for n in os.listdir(GOLDEN_DIR)
            if n.endswith(".in.txt")
        }
        for prefix in CASES:
            # pass/clean/ok vs fail/issues/violations/failed variants
            self.assertTrue(
                any(n.startswith(prefix + "_") for n in names),
                "profile %r has no golden fixture" % prefix,
            )

    def test_xcodebuild_build_failure_keeps_error_messages(self):
        # Red gate: the compactor must never swallow build errors.
        with open(
            os.path.join(GOLDEN_DIR, "xcodebuild_failed.in.txt"),
            encoding="utf-8",
        ) as handle:
            text = handle.read()
        out = CASES["xcodebuild"](text)
        self.assertIn("error: cannot find 'fetchUserr' in scope", out)
        self.assertIn(
            "error: compilation failed: reference to generic type 'Result'",
            out,
        )
        self.assertIn("** BUILD FAILED ** (2 errors)", out)


if __name__ == "__main__":
    unittest.main()
