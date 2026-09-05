"""Golden byte-for-byte regression baseline for output compactors (TK-50).

Each pair tests/fixtures/golden/<name>.in.txt + <name>.out.txt was generated
by the pre-migration parsers and committed before any migration. Every
compactor — migrated onto compact_profiles and still hand-written — must
reproduce its dump byte-for-byte; a diff means the observable format
silently changed (wave-1 plan red-gate 12 / mutation gate 4).
"""

import os
import unittest

from actx_lib.filters import linter_filter, test_runner_filter

GOLDEN_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "golden"
)


def _test_runner_compact(tool):
    def compact(text):
        return test_runner_filter.compact(text, tool)

    return compact


# case prefix -> compactor under test
CASES = {
    "pytest": _test_runner_compact("pytest"),
    "cargo_test": _test_runner_compact("cargo"),
    "go_test": _test_runner_compact("go"),
    "jest": _test_runner_compact("jest"),
    "vitest": _test_runner_compact("vitest"),
    "ruff": linter_filter.compact_ruff,
    "tsc": linter_filter.compact_tsc,
    "eslint": linter_filter.compact_eslint,
    "golangci": linter_filter.compact_golangci_lint,
    "cargo_build": linter_filter.compact_cargo,
    "cargo_clippy": linter_filter.compact_cargo,
    "next": linter_filter.compact_next,
}


def _case_for(name):
    for prefix in sorted(CASES, key=len, reverse=True):
        if name.startswith(prefix + "_"):
            return prefix
    raise AssertionError("golden dump %r matches no compactor case" % name)


class GoldenCompactorTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
