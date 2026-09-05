"""TK-43: data-stack E2E on shim executables (tmp PATH, no network).

DoD observability: SQL table compaction with column masking, containment
verification of data fidelity (H-F5: every cell value a substring, row
count preserved, header preserved, masked columns excluded), bq/terraform/
redis/dbt paths, hook ask/allow decisions, T1 reds on data-credential
files, exit codes, and the redaction -> compression -> truncate order.
"""

import json
import os
import stat
import subprocess
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")

BASE_CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}


def render_table(headers, rows):
    """Render a psql-style framed table from cell data."""
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    frame = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def render_row(cells):
        return "| " + " | ".join(
            cell.ljust(w) for cell, w in zip(cells, widths)
        ) + " |"

    out = [frame, render_row(headers), frame]
    for row in rows:
        out.append(render_row(row))
    out.append(frame)
    return "\n".join(out) + "\n"


# The TK-43 data-fidelity edge corpus (DoD addition): NULL/empty cells,
# values with commas and quotes, leading zeros and +-prefixes, unicode,
# a value that looks like a frame, duplicate rows, header==value.
EDGE_HEADERS = ["id", "label", "note"]
EDGE_ROWS = [
    ["1", "alice", "plain"],
    ["2", "", ""],                       # NULL / empty cells
    ["3", "last, first", 'say "hi"'],    # comma + quotes in values
    ["4", "007", "+79130000000"],        # leading zeros, +-prefix
    ["5", "日本語テキスト", "wide"],      # unicode / wide
    ["6", "+---+", "frame-like"],        # value that looks like a frame
    ["6", "+---+", "frame-like"],        # duplicate row: no dedup allowed
    ["id", "label", "note"],             # header == value
]

SECRET_HEADERS = ["id", "username", "password", "api_key"]
SECRET_ROWS = [
    ["1", "alice", "hunter2", "sk-live-abcdef"],
    ["2", "bob", " plaintext9 ", "12345"],
]


def assert_containment(testcase, headers, rows, output, masked_columns=()):
    """H-F5 containment check, in code: (a) every original cell value is a
    substring of the output; (b) the data-row count is preserved; (c) the
    header is preserved; (d) masked secret columns are excluded by header."""
    masked_indexes = {headers.index(name) for name in masked_columns}
    for r, row in enumerate(rows):
        for c, value in enumerate(row):
            if not value:
                continue  # empty cells: covered by the row-count check
            if c in masked_indexes:
                testcase.assertNotIn(value, output, (r, c, value))
            else:
                testcase.assertIn(value, output, (r, c, value))
    header_line = ",".join(headers)
    testcase.assertIn(header_line, output)  # (c) header preserved
    lines = [line for line in output.splitlines() if line.strip()]
    non_header = [
        line
        for line in lines
        if line != header_line and not line.startswith("(")
    ]
    # Data rows textually equal to the header line (the header==value edge)
    # are the occurrences of header_line beyond the first one.
    header_like = sum(1 for line in lines if line == header_line) - 1
    testcase.assertEqual(
        len(non_header) + max(0, header_like), len(rows), output
    )  # (b) row count


class _ShimTestCase(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.bin = tempfile.TemporaryDirectory()
        os.environ["HOME"] = self.home.name
        self.marker = os.path.join(self.bin.name, "shim-ran.marker")

    def tearDown(self):
        del os.environ["HOME"]
        self.bin.cleanup()
        self.home.cleanup()

    def install_shim(self, name, output=None, script="", exit_code=0):
        path = os.path.join(self.bin.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env python3\n")
            handle.write("import os, sys\n")
            handle.write(script)
            if output is not None:
                # sys.stdout.write (not print): the fixture text already
                # carries its exact trailing newline.
                handle.write("sys.stdout.write(%r)\n" % output)
            if exit_code:
                handle.write("sys.exit(%d)\n" % exit_code)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)

    def run_actx(self, args, stdin_text=None, extra_config=None, timeout=30):
        env = os.environ.copy()
        env["HOME"] = self.home.name
        env["PATH"] = self.bin.name + os.pathsep + env.get("PATH", "")
        env["ACTX_MARKER"] = self.marker
        if extra_config is not None:
            config = json.loads(json.dumps(BASE_CONFIG))
            config.update(extra_config)
            path = os.path.join(
                self.home.name, ".config", "actx", "config.json"
            )
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(config, handle)
        return subprocess.run(
            [ACTX] + args,
            input=stdin_text,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )

    def hook(self, command):
        p = self.run_actx(
            ["hook"],
            stdin_text=json.dumps(
                {"tool_name": "Bash", "tool_input": {"command": command}}
            ),
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)["hookSpecificOutput"]


EDGE_TABLE = render_table(EDGE_HEADERS, EDGE_ROWS)
SECRET_TABLE = render_table(SECRET_HEADERS, SECRET_ROWS)


class SqlCliShimE2ETests(_ShimTestCase):
    def test_psql_edge_corpus_compacts_with_full_containment(self):
        self.install_shim("psql", output=EDGE_TABLE)
        p = self.run_actx(["psql", "-c", "SELECT * FROM t"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("+---+", p.stdout.split("id,label")[0])  # frames gone
        assert_containment(self, EDGE_HEADERS, EDGE_ROWS, p.stdout)

    def test_sqlite3_positional_form_compacts(self):
        self.install_shim("sqlite3", output=EDGE_TABLE)
        p = self.run_actx(["sqlite3", "db.sqlite", "SELECT * FROM t"])
        self.assertEqual(p.returncode, 0, p.stderr)
        assert_containment(self, EDGE_HEADERS, EDGE_ROWS, p.stdout)

    def test_duckdb_c_form_compacts(self):
        self.install_shim("duckdb", output=EDGE_TABLE)
        p = self.run_actx(["duckdb", "-c", "SELECT * FROM t"])
        self.assertEqual(p.returncode, 0, p.stderr)
        assert_containment(self, EDGE_HEADERS, EDGE_ROWS, p.stdout)

    def test_empty_table_marker_preserved(self):
        empty = render_table(["id", "name"], [])
        self.install_shim("psql", output=empty)
        p = self.run_actx(["psql", "-c", "SELECT 1 WHERE false"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "id,name\n(0 rows)\n")

    def test_secret_columns_masked_otherwise_contained(self):
        self.install_shim("psql", output=SECRET_TABLE)
        p = self.run_actx(["psql", "-c", "SELECT * FROM users"])
        self.assertEqual(p.returncode, 0, p.stderr)
        assert_containment(
            self,
            SECRET_HEADERS,
            SECRET_ROWS,
            p.stdout,
            masked_columns=("password", "api_key"),
        )
        self.assertNotIn("hunter2", p.stdout)
        self.assertNotIn("sk-live-abcdef", p.stdout)
        self.assertIn("***", p.stdout)
        self.assertIn("alice", p.stdout)

    def test_unframed_output_is_raw_passthrough_at_command_level(self):
        # DoD (д): сомнение -> raw, tested at COMMAND level: psql default
        # border-1 output (no frames) passes through verbatim.
        text = " id | name\n----+-------\n  1 | alice\n(1 row)\n"
        self.install_shim("psql", output=text)
        p = self.run_actx(["psql", "-c", "SELECT 1"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, text)

    def test_exit_code_preserved(self):
        self.install_shim(
            "psql", output="boom\npsql: FATAL: role missing\n", exit_code=3
        )
        p = self.run_actx(["psql", "-c", "SELECT 1"])
        self.assertEqual(p.returncode, 3)
        self.assertIn("psql: FATAL", p.stdout)

    def test_bare_repl_refused_125_without_execution(self):
        self.install_shim(
            "psql",
            script=(
                "open(os.environ['ACTX_MARKER'], 'w').write('x')\n"
                "import time; time.sleep(30)\n"
            ),
        )
        start = time.monotonic()
        p = self.run_actx(["psql"], timeout=10)
        elapsed = time.monotonic() - start
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertLess(elapsed, 3.0)
        self.assertFalse(os.path.exists(self.marker))

    def test_redaction_compression_truncate_order(self):
        # DoD (г): secret cells + a long table through `actx run` (the
        # generic path, the only one with all three stages): line redaction
        # first (pattern-word header and secret-bearing rows drop), then
        # the lossless collapse, then the explicit truncation marker - and
        # the tail values beyond the marker survive.
        rows = [["%d" % i, "value-%d" % i, "note"] for i in range(250)]
        rows[7][2] = "password=hunter2"
        rows[8][2] = "password=hunter2"
        table = render_table(["id", "name", "password"], rows)
        self.install_shim("psql", output=table)
        p = self.run_actx(
            ["run", "psql", "-c", "SELECT * FROM users"],
            extra_config={"truncate": {"max_lines": 50, "max_line_chars": 300}},
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("truncated:", p.stdout)  # marker preserved
        self.assertIn("value-249", p.stdout)  # tail value beyond the marker
        self.assertIn("value-0", p.stdout)  # head value
        # Redaction ran BEFORE the cap: the pattern-word header and the
        # secret-bearing lines are gone. (A patternless secret VALUE would
        # survive this generic path - the documented Q2 gap; value-level
        # masking is the compact data path, covered by
        # test_secret_columns_masked_otherwise_contained.)
        self.assertNotIn("hunter2", p.stdout)
        self.assertNotIn("password", p.stdout)


class BqShimE2ETests(_ShimTestCase):
    def test_json_ls_compacts(self):
        payload = json.dumps([{"tableId": "t%02d" % i} for i in range(60)])
        self.install_shim("bq", output=payload)
        p = self.run_actx(["bq", "--format=json", "ls", "mydataset"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("items omitted", p.stdout)
        self.assertEqual(json.loads(p.stdout)[0], {"tableId": "t00"})

    def test_query_dry_run_compacts_text(self):
        output = "Query successfully validated. Assuming the tables are not modified, running this query will process 123 bytes of data.\n"
        self.install_shim("bq", output=output)
        p = self.run_actx(["bq", "query", "--dry_run", "SELECT 1"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("123 bytes", p.stdout)


class TerraformShimE2ETests(_ShimTestCase):
    def test_plan_compacts_repeated_lines(self):
        plan = (
            "Terraform used the selected providers to generate the following execution plan.\n"
            + "  + resource \"aws_instance\" \"web\" {}\n" * 200
        )
        self.install_shim("terraform", output=plan)
        p = self.run_actx(["terraform", "plan"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("(x200)", p.stdout)
        self.assertIn("execution plan", p.stdout)

    def test_hook_apply_state_and_plan_out_ask(self):
        for command in (
            "terraform apply",
            "terraform destroy",
            "terraform state rm x",
            "terraform plan -out tfplan",
        ):
            with self.subTest(command=command):
                decision = self.hook(command)
                self.assertEqual(decision["permissionDecision"], "ask", command)
                self.assertIn("terraform", decision["permissionDecisionReason"])

    def test_hook_plan_allows_without_rewrite(self):
        decision = self.hook("terraform plan")
        # RO verb with no compaction gain pre-verified -> hook defers
        # (allow) or rewrites; both acceptable, never ask/deny.
        self.assertIn(decision["permissionDecision"], ("allow", None))


class RedisShimE2ETests(_ShimTestCase):
    def test_exists_rewrites_and_runs(self):
        self.install_shim(
            "redis-cli",
            script="open(os.environ['ACTX_MARKER'], 'w').write('x')\n",
            output="(integer) 1\n",
        )
        p = self.run_actx(["redis-cli", "EXISTS", "session:42"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("(integer) 1", p.stdout)
        self.assertTrue(os.path.exists(self.marker))

    def test_get_refused_125_without_execution(self):
        self.install_shim(
            "redis-cli",
            script="open(os.environ['ACTX_MARKER'], 'w').write('x')\n",
            output="super-secret-value\n",
        )
        p = self.run_actx(["redis-cli", "GET", "api:token"], timeout=10)
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertFalse(os.path.exists(self.marker))
        self.assertNotIn("super-secret-value", p.stdout + p.stderr)

    def test_monitor_refused_125(self):
        self.install_shim(
            "redis-cli",
            script=(
                "open(os.environ['ACTX_MARKER'], 'w').write('x')\n"
                "import time; time.sleep(30)\n"
            ),
        )
        start = time.monotonic()
        p = self.run_actx(["redis-cli", "MONITOR"], timeout=10)
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertLess(time.monotonic() - start, 3.0)
        self.assertFalse(os.path.exists(self.marker))

    def test_hook_flushall_asks(self):
        decision = self.hook("redis-cli FLUSHALL")
        self.assertEqual(decision["permissionDecision"], "ask")
        self.assertIn("redis-cli", decision["permissionDecisionReason"])


class DbtShimE2ETests(_ShimTestCase):
    OUTPUT = """\
20:34:56  Running with dbt=1.8.2
20:34:57  1 of 2 OK created sql table model main.stg_orders ...... [SELECT 87 in 0.08s]
20:34:58  2 of 2 ERROR creating sql view model main.stg_customers . [ERROR in 0.12s]
  Database Error in model stg_customers (models/staging/stg_customers.sql)
    relation "raw_customers" does not exist
20:35:01  Done. PASS=1 WARN=0 ERROR=1 SKIP=0 TOTAL=2
"""

    def test_run_compacts_failures_only(self):
        self.install_shim("dbt", output=self.OUTPUT)
        p = self.run_actx(["dbt", "run"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("ERROR creating sql view model", p.stdout)
        self.assertIn("1 failed, 1 passed", p.stdout)
        self.assertNotIn("OK created", p.stdout)
        self.assertNotIn("Running with dbt", p.stdout)

    def test_hook_deps_asks_t5(self):
        # The TK-51 matrix row is live now that the dbt head ships (E5).
        decision = self.hook("dbt deps")
        self.assertEqual(decision["permissionDecision"], "ask")
        self.assertIn("dbt deps", decision["permissionDecisionReason"])


class HookSqlDecisionTests(_ShimTestCase):
    def test_hook_dangerous_sql_asks(self):
        for command in (
            'psql -c "DROP TABLE users"',
            'sqlite3 db.sqlite "DELETE FROM t"',
            'duckdb -c "TRUNCATE t"',
        ):
            with self.subTest(command=command):
                decision = self.hook(command)
                self.assertEqual(decision["permissionDecision"], "ask")
                self.assertIn("SQL", decision["permissionDecisionReason"])

    def test_hook_ro_sql_rewrites(self):
        decision = self.hook('psql -c "SELECT count(*) FROM t;"')
        self.assertEqual(decision["permissionDecision"], "allow")
        self.assertEqual(
            decision["updatedInput"]["command"],
            'actx psql -c "SELECT count(*) FROM t;"',
        )
        decision = self.hook('sqlite3 db.sqlite "SELECT 1"')
        self.assertEqual(decision["permissionDecision"], "allow")
        self.assertIn("updatedInput", decision)


class DataCredentialT1RedTests(_ShimTestCase):
    """Red-gate 8: the data-credential files stay protected (TK-35)."""

    def test_pgpass_and_terraform_state_and_tfvars_deny(self):
        for command in (
            "cat ~/.pgpass",
            "cat terraform.tfstate",
            "cat prod.tfvars",
            "cat /Users/x/.pgpass",
        ):
            with self.subTest(command=command):
                decision = self.hook(command)
                self.assertEqual(decision["permissionDecision"], "deny")
                self.assertIn("T1_CREDENTIAL_ACCESS", decision["permissionDecisionReason"])


if __name__ == "__main__":
    unittest.main()
