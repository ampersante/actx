"""TK-43: quote-aware rewriter guard for SQL heads (wave-2 plan section 3,
H-F1/N-F8, REQ-06) + SQL dispatch predicates + dbt."""

import unittest

from actx_lib import rewriter


class SqlGuardRewriteTests(unittest.TestCase):
    def assert_rewrite(self, command):
        self.assertEqual(rewriter.rewrite(command), "actx " + command, command)

    def assert_none(self, command):
        self.assertIsNone(rewriter.rewrite(command), command)

    def test_quoted_ro_sql_with_metachars_rewrites(self):
        for command in (
            'psql -c "SELECT count(*) FROM t;"',
            "psql -c 'SELECT 1; SELECT 2'",
            'psql -c "WITH x AS (SELECT 1) SELECT * FROM x;"',
            'psql mydb -c "SELECT 1;"',
            'duckdb -c "SELECT 1;"',
            'duckdb db.duckdb -c "SHOW TABLES;"',
            'sqlite3 db.sqlite "SELECT 1;"',
            'sqlite3 :memory: "SELECT count(*) FROM t;"',
        ):
            with self.subTest(command=command):
                self.assert_rewrite(command)

    def test_unquoted_metachar_injection_rejected(self):
        # Red-gate 13: the semicolon sits in an unquoted token.
        self.assert_none("psql -c SELECT 1; rm -rf /")
        self.assert_none("psql -c SELECT 1 && echo pwned")
        self.assert_none('psql -c SELECT "1" ; rm -rf /')

    def test_unclosed_quote_rejected(self):
        self.assert_none('psql -c "SELECT 1')
        self.assert_none('psql -c "SELECT 1; DROP TABLE x')

    def test_non_sql_heads_keep_strict_guard(self):
        # Red-gate 13 (REQ-06): the quoted guard widens SQL heads ONLY.
        self.assert_none('git commit -m "fix; drop"')
        self.assert_none('grep "a; rm" f')
        self.assert_none('docker ps; rm -rf /')
        self.assert_none('dbt run --select "a; rm -rf /"')

    def test_dangerous_payload_never_rewrites(self):
        for command in (
            'psql -c "DROP TABLE x"',
            "psql -c 'DELETE FROM t'",
            'psql -c "UPDATE t SET a=1"',
            'psql -c "INSERT INTO t VALUES (1)"',
            'psql -c "ALTER TABLE t ADD c int"',
            'psql -c "GRANT ALL ON t TO u"',
            'psql -c "TRUNCATE t"',
            'psql -c "WITH x AS (DELETE FROM t) SELECT 1"',
            'psql -c "SELECT 1; DROP TABLE x"',
            'psql -c "SET ROLE admin"',
            'psql -c "SET SESSION AUTHORIZATION \'u\'"',
            'psql -c "\\! rm -rf ~/"',
            'psql -c "\\copy (SELECT 1) TO \'/tmp/x\'"',
            'sqlite3 db.sqlite ".shell rm -rf /"',
            'sqlite3 db.sqlite ".read dump.sql"',
            'sqlite3 db.sqlite "DROP TABLE t"',
            'duckdb -c "DELETE FROM t"',
            # worst-of-both-payloads: the second -c kills the rewrite
            'psql -c "SELECT 1" -c "DROP TABLE x"',
        ):
            with self.subTest(command=command):
                self.assert_none(command)

    def test_default_deny_unclassified_payload(self):
        # Red-gate 15: COMMENT/PRAGMA/BEGIN have no RO class.
        self.assert_none("psql -c \"COMMENT ON TABLE t IS 'x'\"")
        self.assert_none('sqlite3 db.sqlite "PRAGMA table_info(t)"')
        self.assert_none('psql -c "BEGIN"')

    def test_set_session_local_rewrites(self):
        # H-F15 compromise: search_path & friends are session-local.
        self.assert_rewrite('psql -c "SET search_path=public"')
        self.assert_rewrite("psql -c 'SET timezone=UTC'")

    def test_file_sql_never_rewrites(self):
        self.assert_none("psql -f dump.sql")
        self.assert_none("psql --file dump.sql")
        self.assert_none('psql -c "SELECT 1" -f x.sql')
        self.assert_none("sqlite3 db.sqlite -init dump.sql")
        self.assert_none("duckdb -init dump.sql db.duckdb")

    def test_repl_forms_never_rewrite(self):
        self.assert_none("psql")
        self.assert_none("psql mydb")
        self.assert_none("sqlite3 db.sqlite")
        self.assert_none("duckdb")
        self.assert_none("duckdb db.duckdb")

    def test_safe_metas_rewrite(self):
        self.assert_rewrite('psql -c "\\dt"')
        self.assert_rewrite('psql -c "\\d users"')
        self.assert_rewrite('psql -c "\\conninfo"')

    def test_unquoted_metachar_free_sql_rewrites(self):
        # No metachars at all: byte-identical old path through the predicate.
        # (A metachar-free payload cannot carry `SELECT 1` unquoted - the
        # space splits tokens - so only single-token forms exist here.)
        self.assert_rewrite('psql --command "SELECT 1"')
        self.assert_rewrite("psql -c SELECT")

    def test_equals_command_form(self):
        # =-form rewrites only when metachar-free (the quote guard does not
        # model the =-form payload; documented limitation).
        self.assert_rewrite("psql --command=SELECT")
        self.assert_none('psql --command="SELECT 1; DROP TABLE x"')

    def test_payload_outside_single_quoted_token_rejected(self):
        # Extra positional after the quoted payload: not the guard shape.
        self.assert_none('sqlite3 db.sqlite "SELECT 1" extra')


class DbtRewriteTests(unittest.TestCase):
    def test_run_test_build_rewrite(self):
        for command in ("dbt run", "dbt test", "dbt build",
                        "dbt run --select stg_orders"):
            with self.subTest(command=command):
                self.assertEqual(
                    rewriter.rewrite(command), "actx " + command
                )

    def test_other_verbs_not_rewritten(self):
        for command in ("dbt deps", "dbt compile", "dbt debug", "dbt"):
            with self.subTest(command=command):
                self.assertIsNone(rewriter.rewrite(command))


if __name__ == "__main__":
    unittest.main()
