"""TK-43: security gate _check_sql (T6_HIGH_RISK_SQL) matrix + latency."""

import time
import unittest
from unittest import mock

from actx_lib import security_gate


def evaluate(command):
    return security_gate.evaluate_security(command)


class SqlGateAskTests(unittest.TestCase):
    def assert_ask(self, command):
        decision = evaluate(command)
        self.assertEqual(decision.decision, "ask", command)
        self.assertEqual(decision.category, "T6_HIGH_RISK_SQL", command)

    def test_dangerous_verb_matrix_asks(self):
        for verb in (
            "DROP", "TRUNCATE", "DELETE", "UPDATE", "INSERT", "ALTER",
            "GRANT", "REVOKE", "CREATE", "REPLACE", "MERGE", "COPY",
            "VACUUM", "REINDEX", "CALL", "DO", "COMMENT", "REFRESH",
            "CLUSTER", "LOCK",
        ):
            for command in (
                'psql -c "%s TABLE x"' % verb,
                'sqlite3 db.sqlite "%s FROM t"' % verb,
                'duckdb -c "%s FROM t"' % verb,
            ):
                with self.subTest(command=command):
                    self.assert_ask(command)

    def test_worst_statement_asks(self):
        self.assert_ask('psql -c "SELECT 1; DROP TABLE x"')
        self.assert_ask('psql -c "SELECT 1" -c "DROP TABLE x"')
        self.assert_ask('psql -c "WITH x AS (DELETE FROM t) SELECT 1"')

    def test_cte_behind_chunk_normalization_asks(self):
        # H-F2: the hook path re-spaces `;` before tokenization; the
        # whole-chunk scan stays decisive.
        self.assert_ask('psql -c "SELECT 1;DELETE FROM t"')

    def test_privilege_set_asks(self):
        self.assert_ask('psql -c "SET ROLE admin"')
        self.assert_ask('psql -c "SET SESSION AUTHORIZATION \'u\'"')
        self.assert_ask('sqlite3 db.sqlite "SELECT 1; SET ROLE admin"')

    def test_metacommands_ask(self):
        for command in (
            'psql -c "\\! rm -rf ~/"',
            'psql -c "\\copy (SELECT 1) TO \'/tmp/x\'"',
            'psql -c "\\i dump.sql"',
            'psql -c "\\o /tmp/out"',
            'psql -c "\\gexec"',
            'psql -c "\\watch"',
            'psql -c "\\set x 1"',
            'sqlite3 db.sqlite ".shell rm -rf /"',
            'sqlite3 db.sqlite ".system rm -rf /"',
            'sqlite3 db.sqlite ".read dump.sql"',
            'sqlite3 db.sqlite ".import data.csv t"',
            'sqlite3 db.sqlite ".once /tmp/x"',
            'sqlite3 db.sqlite ".output /tmp/x"',
            'sqlite3 db.sqlite ".backup main.bak"',
        ):
            with self.subTest(command=command):
                self.assert_ask(command)

    def test_file_based_sql_asks(self):
        for command in (
            "psql -f dump.sql",
            "psql --file dump.sql",
            "psql --file=dump.sql",
            'psql -c "SELECT 1" -f x.sql',
            "sqlite3 db.sqlite -init dump.sql",
            "duckdb -init dump.sql db.duckdb",
        ):
            with self.subTest(command=command):
                self.assert_ask(command)

    def test_pg_restore_asks(self):
        for command in (
            "pg_restore -d mydb dump.bin",
            "pg_restore --list dump.bin",
        ):
            with self.subTest(command=command):
                self.assert_ask(command)

    def test_default_deny_asks(self):
        # Red-gate 15: no explicit RO class.
        for command in (
            'psql -c "COMMENT ON TABLE t IS \'x\'"',
            'sqlite3 db.sqlite "PRAGMA table_info(t)"',
            'psql -c "BEGIN"',
            'duckdb -c "EXEC sp"',
        ):
            with self.subTest(command=command):
                self.assert_ask(command)

    def test_gate_error_asks_not_fails_open(self):
        # N-F8: the outer fail-open returning allow is unacceptable for SQL
        # heads - any internal error must land on ask.
        with mock.patch.object(
            security_gate.sql_verbs,
            "danger_reason",
            side_effect=RuntimeError("boom"),
        ):
            decision = evaluate('psql -c "SELECT 1"')
        self.assertEqual(decision.decision, "ask")
        self.assertEqual(decision.category, "T6_HIGH_RISK_SQL")


class SqlGateAllowTests(unittest.TestCase):
    def assert_allow(self, command):
        decision = evaluate(command)
        self.assertEqual(decision.decision, "allow", (command, decision.reason))

    def test_ro_sql_allows(self):
        for command in (
            'psql -c "SELECT 1"',
            'psql -c "SELECT count(*) FROM t;"',
            'psql -c "SHOW tables"',
            'psql -c "EXPLAIN SELECT 1"',
            'psql -c "TABLE users"',
            'psql -c "WITH x AS (SELECT 1) SELECT * FROM x"',
            'psql -c "\\dt"',
            'psql -c "\\conninfo"',
            'psql -c "SET search_path=public"',
            'psql -c "SELECT 1; SELECT 2"',
            'psql -d mydb -U alice -c "SELECT 1"',
            'sqlite3 db.sqlite "SELECT 1"',
            'sqlite3 :memory: "SELECT count(*) FROM t"',
            'sqlite3 -json db.sqlite "SELECT 1"',
            'duckdb -c "SELECT 1"',
            'duckdb db.duckdb -c "SHOW TABLES"',
        ):
            with self.subTest(command=command):
                self.assert_allow(command)

    def test_repl_and_info_forms_allow(self):
        # Bare REPLs and flag-only listings carry no payload: the hang
        # policy owns interactivity (never-wrap, exit 125).
        for command in (
            "psql",
            "psql mydb",
            "psql -l",
            "psql --version",
            "sqlite3 db.sqlite",
            "sqlite3 --version",
            "duckdb",
            "duckdb db.duckdb",
        ):
            with self.subTest(command=command):
                self.assert_allow(command)

    def test_actx_prefix_unwrapped_for_sql_gate(self):
        self.assertEqual(
            evaluate('actx run psql -c "DROP TABLE x"').decision, "ask"
        )
        self.assertEqual(
            evaluate('actx psql -c "SELECT 1"').decision, "allow"
        )

    def test_unrelated_heads_with_sql_words_allow(self):
        for command in (
            "echo DROP TABLE x",
            "cat schema_notes.txt",
            "git commit -m 'drop table'",
        ):
            with self.subTest(command=command):
                self.assert_allow(command)

    def test_word_boundary_avoids_common_fps(self):
        self.assert_allow('psql -d create_db -c "SELECT 1"')
        self.assert_allow('sqlite3 updated_at.sqlite "SELECT 1"')


class SqlGateLatencyTests(unittest.TestCase):
    def test_gate_under_1ms(self):
        # PRD 12/13.10 budget for the gate incl. the new SQL pre-filter.
        for command in (
            'psql -c "SELECT 1"',
            'sqlite3 db.sqlite "SELECT 1"',
            "git status",
            "docker ps",
        ):
            with self.subTest(command=command):
                start = time.perf_counter()
                for _ in range(1000):
                    evaluate(command)
                elapsed = (time.perf_counter() - start) / 1000 * 1000
                self.assertLess(elapsed, 1.0, "%.4f ms/op" % elapsed)


if __name__ == "__main__":
    unittest.main()
