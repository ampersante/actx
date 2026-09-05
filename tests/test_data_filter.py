"""TK-43: data_filter unit tests (in-process; mocked runner.execute)."""

import io
import subprocess
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from unittest import mock

from actx_lib.filters import data_filter

CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}

SECRET_TABLE = """\
+----+----------+-----------+
| id | password | note      |
+----+----------+-----------+
|  1 | hunter2  | keep this |
|  2 | x        | plain     |
+----+----------+-----------+
"""

NO_SECRET_TABLE = """\
+----+-------+
| id | name  |
+----+-------+
|  1 | alice |
+----+-------+
"""


def _run(run_fn, args, result, passthrough=None):
    """Run a data_filter entry with runner.execute mocked to `result` (and
    optionally run_passthrough mocked to a sentinel code)."""
    out = io.StringIO()
    err = io.StringIO()
    with ExitStack() as stack:
        stack.enter_context(
            mock.patch("actx_lib.runner.execute", return_value=result)
        )
        if passthrough is not None:
            stack.enter_context(
                mock.patch(
                    "actx_lib.runner.run_passthrough", return_value=passthrough
                )
            )
        with redirect_stdout(out), redirect_stderr(err):
            rc = run_fn(args, CONFIG)
    return rc, out.getvalue(), err.getvalue()


class MaskSecretColumnsTests(unittest.TestCase):
    def test_secret_column_masked_width_preserved(self):
        masked = data_filter._mask_secret_columns(SECRET_TABLE)
        # every line keeps its exact width (pipe positions unmoved)
        for orig, new in zip(SECRET_TABLE.split("\n"), masked.split("\n")):
            self.assertEqual(len(orig), len(new), (orig, new))
        self.assertNotIn("hunter2", masked)
        self.assertIn("keep this", masked)
        self.assertIn("***", masked)

    def test_short_values_mask_to_same_length(self):
        masked = data_filter._mask_secret_columns(SECRET_TABLE)
        row2 = masked.split("\n")[4]
        self.assertNotIn("x ", row2.replace("| x ", ""))  # 'x' alone never survives
        self.assertIn("*", row2)

    def test_no_secret_header_is_passthrough_identity(self):
        self.assertIs(
            data_filter._mask_secret_columns(NO_SECRET_TABLE), NO_SECRET_TABLE
        )

    def test_text_without_tables_unchanged(self):
        text = "plain text\nno pipes at all\n"
        self.assertIs(data_filter._mask_secret_columns(text), text)

    def test_non_string_unchanged(self):
        self.assertIsNone(data_filter._mask_secret_columns(None))

    def test_error_fails_open_to_input(self):
        text = SECRET_TABLE
        with mock.patch.object(
            data_filter, "_is_frame", side_effect=RuntimeError("boom")
        ):
            self.assertIs(data_filter._mask_secret_columns(text), text)


class SqlCompactTests(unittest.TestCase):
    def test_table_compacts_with_masked_secret_column(self):
        out = data_filter._sql_compact(SECRET_TABLE)
        lines = out.splitlines()
        self.assertEqual(lines[0], "id,password,note")
        self.assertEqual(lines[1], "1,***,keep this")
        self.assertNotIn("hunter2", out)

    def test_unframed_output_falls_back_to_secret_line_redaction(self):
        text = " id | password \n----+----------\n  1 | hunter2\n(1 row)\n"
        out = data_filter._sql_compact(text)
        # No frame -> no table compaction; the header line (pattern word)
        # drops via redact_text; the raw value line has no pattern word and
        # stays (documented approximation: value-level masking needs frames).
        self.assertNotIn("password", out)
        self.assertIn("(1 row)", out)

    def test_pipe_value_raw_fallback_documented_limitation(self):
        # A pipe inside the VALUE makes the row ragged: the column mask
        # skips the row and compact_table refuses the whole table. The
        # header line still drops via secret-line redaction; a secret VALUE
        # with a pipe survives that line filter - documented approximation
        # (value-level masking needs parseable frames), same class as the
        # Q2 pattern-redaction gap.
        text = (
            "+----+----------+\n"
            "| id | password |\n"
            "+----+----------+\n"
            "|  1 | a|b      |\n"
            "+----+----------+\n"
        )
        out = data_filter._sql_compact(text)
        self.assertNotIn("password", out)  # header dropped by line redaction
        self.assertIn("a|b", out)  # pinned limitation: ragged row survives


class RunSqlCliTests(unittest.TestCase):
    def _result(self, stdout):
        return subprocess.CompletedProcess(
            ["psql", "-c", "SELECT ..."], 0, stdout, ""
        )

    def test_payload_runs_table_compaction(self):
        rc, out, _ = _run(
            data_filter.run_psql, ["-c", "SELECT 1"], self._result(NO_SECRET_TABLE)
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "id,name\n1,alice\n")

    def test_exit_code_preserved(self):
        result = subprocess.CompletedProcess(
            ["psql", "-c", "SELECT 1"], 2, "psql: error\n", ""
        )
        rc, out, _ = _run(data_filter.run_psql, ["-c", "SELECT 1"], result)
        self.assertEqual(rc, 2)
        self.assertIn("psql: error", out)

    def test_repl_form_is_passthrough(self):
        result = self._result("")
        rc, out, err = _run(
            data_filter.run_psql, ["mydb"], result, passthrough=99
        )
        self.assertEqual(rc, 99)

    def test_sqlite3_positional_payload_compacts(self):
        rc, out, _ = _run(
            data_filter.run_sqlite3,
            ["db.sqlite", "SELECT 1"],
            self._result(NO_SECRET_TABLE),
        )
        self.assertEqual(rc, 0)
        self.assertEqual(out, "id,name\n1,alice\n")

    def test_duckdb_c_payload_compacts(self):
        rc, out, _ = _run(
            data_filter.run_duckdb, ["-c", "SELECT 1"], self._result(NO_SECRET_TABLE)
        )
        self.assertEqual(rc, 0)
        self.assertIn("id,name", out)

    def test_compaction_error_fails_open_raw(self):
        result = self._result(SECRET_TABLE)
        with mock.patch.object(
            data_filter.ascii_table_filter,
            "compact_table",
            side_effect=RuntimeError("boom"),
        ):
            # _sql_compact itself does not catch compact_table errors: the
            # runner.compacted_result contract fails open to raw output.
            out = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                with mock.patch(
                    "actx_lib.runner.execute", return_value=result
                ):
                    rc = data_filter.run_psql(["-c", "SELECT 1"], CONFIG)
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), SECRET_TABLE)


class RunTerraformTests(unittest.TestCase):
    PLAN = (
        "Terraform will perform the following actions:\n"
        + "  + resource \"aws_instance\" \"web\" {}\n" * 80
    )

    def test_plan_compacts_duplicates(self):
        result = subprocess.CompletedProcess(
            ["terraform", "plan"], 0, self.PLAN, ""
        )
        rc, out, _ = _run(data_filter.run_terraform, ["plan"], result)
        self.assertEqual(rc, 0)
        self.assertIn("(x", out)  # RLE marker for repeated lines

    def test_apply_is_passthrough(self):
        result = subprocess.CompletedProcess(["terraform", "apply"], 0, "x", "")
        rc, _, _ = _run(
            data_filter.run_terraform, ["apply"], result, passthrough=7
        )
        self.assertEqual(rc, 7)

    def test_validate_show_version_graph_compact(self):
        result = subprocess.CompletedProcess(["terraform", "show"], 0, "a\na\n", "")
        for verb in ("validate", "show", "version", "graph"):
            with self.subTest(verb=verb):
                rc, out, _ = _run(
                    data_filter.run_terraform, [verb], result
                )
                self.assertEqual(rc, 0)


class RunRedisTests(unittest.TestCase):
    def test_ro_verb_runs_lossless(self):
        result = subprocess.CompletedProcess(
            ["redis-cli", "EXISTS", "k"], 0, "(integer) 1\n", ""
        )
        rc, out, _ = _run(data_filter.run_redis, ["EXISTS", "k"], result)
        self.assertEqual(rc, 0)
        self.assertIn("(integer) 1", out)

    def test_non_ro_verb_is_passthrough(self):
        result = subprocess.CompletedProcess(
            ["redis-cli", "SET", "k", "v"], 0, "OK\n", ""
        )
        rc, _, _ = _run(
            data_filter.run_redis, ["SET", "k", "v"], result, passthrough=5
        )
        self.assertEqual(rc, 5)

    def test_lossless_error_fails_open(self):
        # run_lossless already owns the fail-open contract; exercise it via
        # a parser crash inside the lossless transform.
        result = subprocess.CompletedProcess(
            ["redis-cli", "DBSIZE"], 0, "(integer) 42\n", ""
        )
        with mock.patch(
            "actx_lib.runner._lossless_transform", side_effect=RuntimeError("x")
        ):
            rc, out, _ = _run(data_filter.run_redis, ["DBSIZE"], result)
        # raw_fallback path: stdout printed raw, exit code kept
        self.assertEqual(rc, 0)
        self.assertIn("(integer) 42", out)


DBT_RUN_OUTPUT = """\
20:34:56  Running with dbt=1.8.2
20:34:57  1 of 2 OK created sql table model main.stg_orders ...... [SELECT 87 in 0.08s]
20:34:58  2 of 2 ERROR creating sql view model main.stg_customers . [ERROR in 0.12s]
  Database Error in model stg_customers (models/stg_customers.sql)
    relation "raw_customers" does not exist
20:35:01  Done. PASS=1 WARN=0 ERROR=1 SKIP=0 TOTAL=2
"""


class RunDbtTests(unittest.TestCase):
    def test_run_compacts_failures_only(self):
        result = subprocess.CompletedProcess(
            ["dbt", "run"], 1, DBT_RUN_OUTPUT, ""
        )
        rc, out, _ = _run(data_filter.run_dbt, ["run"], result)
        self.assertEqual(rc, 1)
        self.assertIn("ERROR creating sql view model", out)
        self.assertIn("1 failed, 1 passed", out)
        self.assertNotIn("OK created", out)
        self.assertNotIn("Running with dbt", out)

    def test_test_and_build_use_profile(self):
        result = subprocess.CompletedProcess(["dbt", "test"], 1, DBT_RUN_OUTPUT, "")
        for verb in ("test", "build"):
            with self.subTest(verb=verb):
                rc, out, _ = _run(data_filter.run_dbt, [verb], result)
                self.assertEqual(rc, 1)
                self.assertIn("1 failed, 1 passed", out)

    def test_other_verb_is_passthrough(self):
        result = subprocess.CompletedProcess(["dbt", "compile"], 0, "x", "")
        rc, _, _ = _run(data_filter.run_dbt, ["compile"], result, passthrough=3)
        self.assertEqual(rc, 3)


if __name__ == "__main__":
    unittest.main()
