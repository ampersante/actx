import unittest

from actx_lib.filters import compact_profiles

PYTEST_SUMMARY = """\
=== short test summary info ===
FAILED test_b.py::test_two - assert 2 == 3
FAILED test_a.py::test_one - assert 1 == 2
=== 1 failed, 1 passed ===
"""

RUFF = """\
src/main.py:3:1: F401 `os` imported but unused
src/main.py:5:1: E501 Line too long (89 > 88)
Found 2 errors.
"""

TSC = """\
src/foo.ts(3,5): error TS2304: Cannot find name 'console'.
src/bar.ts(10,1): error TS2322: Type 'string' is not assignable to type 'number'.
"""

GOLANGCI = """\
pkg/foo.go:10:3: S1021: should merge variable declaration (gosimple)
pkg/bar.go:20:5: revive: exported function Foo should have comment
"""

# Synthetic `dbt run` output. The point of this fixture: the "dbt_run"
# profile in compact_profiles.PROFILES is data only — connecting dbt
# required zero engine code (TK-50 DoD; groundwork for TK-43).
DBT_RUN = """\
20:34:56  Running with dbt=1.8.2
20:34:56  Found 12 models, 4 data tests
20:34:57  1 of 15 START sql table model main.stg_orders .................... [CREATE TABLE]
20:34:57  1 of 15 OK created sql table model main.stg_orders .............. [SELECT 87 in 0.08s]
20:34:58  2 of 15 ERROR creating sql table model main.stg_customers ....... [ERROR in 0.12s]
  Database Error in model stg_customers (models/staging/stg_customers.sql)
    relation "raw_customers" does not exist
20:34:59  3 of 15 OK created sql view model main.stg_payments ............. [SELECT 40 in 0.05s]
20:35:00  4 of 15 ERROR creating sql table model main.stg_charges .......... [ERROR in 0.09s]
  Database Error in model stg_charges (models/staging/stg_charges.sql)
    relation "raw_charges" does not exist
20:35:01  Completed with 2 errors
20:35:01  Done. PASS=13 WARN=0 ERROR=2 SKIP=0 TOTAL=15
"""


class TestRunnerProfileTests(unittest.TestCase):
    def test_pytest_profile_summary_grouped_by_file_sorted(self):
        data = compact_profiles.parse_test(
            PYTEST_SUMMARY, compact_profiles.PROFILES["pytest"]
        )
        self.assertEqual(
            data["failures"],
            "test_a.py:\n"
            "  test_a.py::test_one - assert 1 == 2\n"
            "test_b.py:\n"
            "  test_b.py::test_two - assert 2 == 3",
        )
        self.assertEqual(data["failed"], 1)
        self.assertEqual(data["passed"], 1)

    def test_pytest_profile_counts_errors_into_failed(self):
        data = compact_profiles.parse_test(
            "2 failed, 1 error, 10 passed in 0.1s",
            compact_profiles.PROFILES["pytest"],
        )
        self.assertEqual(data["failed"], 3)
        self.assertEqual(data["passed"], 10)
        self.assertEqual(data["failures"], "")

    def test_cargo_profile_sums_counters_across_suites(self):
        text = (
            "test result: FAILED. 4 passed; 1 failed; 0 ignored\n"
            "test result: FAILED. 2 passed; 3 failed; 0 ignored\n"
        )
        data = compact_profiles.parse_test(
            text, compact_profiles.PROFILES["cargo_test"]
        )
        self.assertEqual(data["failed"], 4)
        self.assertEqual(data["passed"], 6)
        self.assertEqual(data["failures"], "")

    def test_dbt_profile_data_only_connection(self):
        data = compact_profiles.parse_test(
            DBT_RUN, compact_profiles.PROFILES["dbt_run"]
        )
        self.assertEqual(
            data["failures"],
            "20:34:58  2 of 15 ERROR creating sql table model main.stg_customers"
            " ....... [ERROR in 0.12s]\n"
            "  Database Error in model stg_customers (models/staging/stg_customers.sql)\n"
            '    relation "raw_customers" does not exist\n'
            "20:35:00  4 of 15 ERROR creating sql table model main.stg_charges"
            " .......... [ERROR in 0.09s]\n"
            "  Database Error in model stg_charges (models/staging/stg_charges.sql)\n"
            '    relation "raw_charges" does not exist',
        )
        self.assertEqual(data["failed"], 2)
        self.assertEqual(data["passed"], 13)
        self.assertNotIn("OK created", data["failures"])
        self.assertNotIn("Running with dbt", data["failures"])

    def test_failure_block_closes_on_non_matching_line(self):
        profile = {
            "failure_start": (r"boom",),
            "failure_continue": (r"^\s+\S",),
            "counters": {},
        }
        data = compact_profiles.parse_test(
            "boom\n  detail\nnoise\nboom\n  more\n", profile
        )
        self.assertEqual(data["failures"], "boom\n  detail\nboom\n  more")


class LinterProfileTests(unittest.TestCase):
    def test_ruff_profile_keeps_matching_lines_and_count(self):
        self.assertEqual(
            compact_profiles.parse_lint(RUFF, compact_profiles.PROFILES["ruff"]),
            "src/main.py:3:1: F401 `os` imported but unused\n"
            "src/main.py:5:1: E501 Line too long (89 > 88)\n"
            "2 errors",
        )

    def test_ruff_profile_clean_output_is_empty(self):
        self.assertEqual(
            compact_profiles.parse_lint(
                "All checks passed!\n", compact_profiles.PROFILES["ruff"]
            ),
            "",
        )

    def test_tsc_profile(self):
        self.assertEqual(
            compact_profiles.parse_lint(TSC, compact_profiles.PROFILES["tsc"]),
            "src/foo.ts(3,5): error TS2304: Cannot find name 'console'.\n"
            "src/bar.ts(10,1): error TS2322: Type 'string' is not assignable"
            " to type 'number'.\n"
            "2 errors",
        )

    def test_golangci_profile(self):
        self.assertEqual(
            compact_profiles.parse_lint(
                GOLANGCI, compact_profiles.PROFILES["golangci"]
            ),
            "pkg/foo.go:10:3: S1021: should merge variable declaration (gosimple)\n"
            "pkg/bar.go:20:5: revive: exported function Foo should have comment\n"
            "2 errors",
        )


class EngineFailOpenTests(unittest.TestCase):
    """The engine must not swallow bad profile data: exceptions propagate so
    the filter's compacted_result path fails open to raw output (RK-03)."""

    def test_parse_test_invalid_regex_raises(self):
        import re

        profile = {"counters": {"failed": (("(d+", 1, "first"),), "passed": ()}}
        with self.assertRaises(re.error):
            compact_profiles.parse_test("text", profile)

    def test_parse_lint_invalid_regex_raises(self):
        import re

        with self.assertRaises(re.error):
            compact_profiles.parse_lint("text", {"keep_line": "(["})

    def test_parse_test_unknown_counter_mode_raises(self):
        profile = {
            "counters": {"failed": ((r"(\d+)", 1, "sometimes"),), "passed": ()}
        }
        with self.assertRaises(ValueError):
            compact_profiles.parse_test("1 2", profile)


if __name__ == "__main__":
    unittest.main()
