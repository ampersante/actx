"""TK-43: sql_verbs classification matrix (REQ-03)."""

import unittest

from actx_lib import sql_verbs

RO = "ro"
ASK = "ask"


class RoClassTests(unittest.TestCase):
    def test_read_only_leading_verbs(self):
        for payload in (
            "SELECT 1",
            "select * from t",
            "SHOW tables",
            "EXPLAIN SELECT 1",
            "VALUES (1), (2)",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "TABLE users",
            "SELECT count(*) FROM t;",
            "  SELECT 1  ",
        ):
            with self.subTest(payload=payload):
                self.assertEqual(sql_verbs.classify_payload(payload), RO)

    def test_safe_psql_metas(self):
        for payload in (
            "\\d",
            "\\dt",
            "\\dt+",
            "\\d t",
            "\\l",
            "\\di",
            "\\du",
            "\\dn",
            "\\df",
            "\\dv",
            "\\z",
            "\\conninfo",
            "\\dt; SELECT 1",
        ):
            with self.subTest(payload=payload):
                self.assertEqual(sql_verbs.classify_payload(payload), RO)

    def test_set_session_locals_are_ro(self):
        # H-F15: `SET search_path` is the harmless mass preamble; a -c
        # payload runs in its own session anyway.
        for payload in (
            "SET search_path=public",
            "set search_path TO public",
            "SET timezone='UTC'",
            "SET LOCAL statement_timeout='30s'",
        ):
            with self.subTest(payload=payload):
                self.assertEqual(sql_verbs.classify_payload(payload), RO)

    def test_multi_statement_all_ro(self):
        self.assertEqual(
            sql_verbs.classify_payload("SELECT 1; SELECT 2; SELECT 3"), RO
        )


class AskClassTests(unittest.TestCase):
    def test_dangerous_verbs_reject_wherever_they_sit(self):
        # Worst-verb over the WHOLE payload (N-F14a): leading, CTE-wrapped
        # and appended-statement positions all ask.
        for payload in (
            "DROP TABLE x",
            "drop table x",
            "TRUNCATE t",
            "DELETE FROM t",
            "UPDATE t SET a=1",
            "INSERT INTO t VALUES (1)",
            "ALTER TABLE t ADD c int",
            "GRANT ALL ON t TO u",
            "REVOKE ALL ON t FROM u",
            "CREATE TABLE t (id int)",
            "REPLACE INTO t VALUES (1)",
            "MERGE INTO t USING s ON 1=1",
            "COPY t FROM 'f.csv'",
            "VACUUM",
            "REINDEX TABLE t",
            "CALL p()",
            "DO $$ BEGIN END $$",
            "COMMENT ON TABLE t IS 'x'",
            "REFRESH MATERIALIZED VIEW v",
            "CLUSTER t USING i",
            "LOCK TABLE t",
            "WITH x AS (DELETE FROM t) SELECT 1",
            "SELECT 1; DROP TABLE x",
            "SELECT 1 ; DELETE FROM t",
        ):
            with self.subTest(payload=payload):
                self.assertEqual(sql_verbs.classify_payload(payload), ASK)

    def test_privilege_set_asks(self):
        for payload in (
            "SET ROLE admin",
            "set role pg_read_all_data",
            "SET SESSION AUTHORIZATION 'u'",
            "SELECT 1; SET ROLE admin",
        ):
            with self.subTest(payload=payload):
                self.assertEqual(sql_verbs.classify_payload(payload), ASK)

    def test_blacklisted_metas_ask(self):
        for payload in (
            "\\! rm -rf ~/",
            "\\copy (SELECT 1) TO '/tmp/x'",
            "\\i dump.sql",
            "\\o /tmp/out",
            "\\gexec",
            "\\g /tmp/x",
            "\\watch",
            "\\set x 1",
            ".shell rm -rf /",
            ".system rm -rf /",
            ".read dump.sql",
            ".import data.csv t",
            ".once /tmp/x",
            ".output /tmp/x",
            ".backup main.bak",
            "SELECT 1; \\! rm -rf /",
        ):
            with self.subTest(payload=payload):
                self.assertEqual(sql_verbs.classify_payload(payload), ASK)

    def test_default_deny_unclassified_statements(self):
        # N-F2a: no explicit RO class -> ask.
        for payload in (
            "",
            "   ",
            "PRAGMA table_info(t)",
            "BEGIN",
            "COMMIT",
            "RESET ROLE",
            "EXEC sp",
            "REASSIGN OWNED BY a TO b",
            "COMMENT",  # bare dangerous verb
        ):
            with self.subTest(payload=payload):
                self.assertEqual(sql_verbs.classify_payload(payload), ASK)

    def test_word_boundary_not_substring(self):
        # `create_db`/`updated_at` are single words: no false dangerous hit.
        self.assertEqual(
            sql_verbs.classify_payload("SELECT create_db FROM updated_at"), RO
        )

    def test_literal_false_positives_ask_safe_direction(self):
        # Documented approximation: `;`/dangerous words inside literals and
        # comments classify by worst statement -> ask (safe direction).
        self.assertEqual(sql_verbs.classify_payload("SELECT ';'"), ASK)
        self.assertEqual(
            sql_verbs.classify_payload("SELECT 1 -- drop later"), ASK
        )

    def test_non_string_input_asks(self):
        self.assertEqual(sql_verbs.classify_payload(None), ASK)
        self.assertEqual(sql_verbs.classify_payload(42), ASK)


class DangerReasonTests(unittest.TestCase):
    def test_reason_for_each_class(self):
        self.assertIsNone(sql_verbs.danger_reason("psql -c 'SELECT 1'"))
        self.assertIn("dangerous SQL verb", sql_verbs.danger_reason("DROP TABLE x"))
        self.assertIn("privilege", sql_verbs.danger_reason("SET ROLE a"))
        self.assertIn("metacommand", sql_verbs.danger_reason("psql -c '\\! rm'"))
        self.assertIn("dot command", sql_verbs.danger_reason(".shell rm"))
        self.assertIsNone(sql_verbs.danger_reason(""))
        self.assertIsNone(sql_verbs.danger_reason(None))

    def test_dot_command_word_boundary(self):
        self.assertIsNone(sql_verbs.danger_reason("see .readme please"))
        self.assertIsNotNone(sql_verbs.danger_reason(".read dump.sql"))

    def test_psql_meta_boundary(self):
        # The blacklist lists exactly the shell/file/stream metas; other
        # unknown metas (like `\dtx`) still ask via default-deny at the
        # classify level, not via danger_reason.
        self.assertIsNone(sql_verbs.danger_reason("\\dt"))
        self.assertIsNone(sql_verbs.danger_reason("\\dtx"))
        self.assertEqual(sql_verbs.classify_payload("\\dtx"), ASK)


class SqlPayloadsTests(unittest.TestCase):
    def test_psql_all_c_payloads(self):
        self.assertEqual(
            sql_verbs.sql_payloads("psql", ["-c", "SELECT 1"]),
            ["SELECT 1"],
        )
        self.assertEqual(
            sql_verbs.sql_payloads("psql", ["-c", "SELECT 1", "-c", "DROP x"]),
            ["SELECT 1", "DROP x"],
        )
        self.assertEqual(
            sql_verbs.sql_payloads("psql", ["--command=SELECT 1"]),
            ["SELECT 1"],
        )

    def test_psql_connection_args_are_not_payloads(self):
        # dbname/user are structure, not SQL: never classified.
        self.assertEqual(
            sql_verbs.sql_payloads("psql", ["-d", "mydb", "-U", "u"]),
            [],
        )

    def test_sqlite3_positional_rule(self):
        self.assertEqual(
            sql_verbs.sql_payloads("sqlite3", ["db.sqlite", "SELECT 1"]),
            ["SELECT 1"],
        )
        # Bare db (1 positional) is the REPL: no payload.
        self.assertEqual(sql_verbs.sql_payloads("sqlite3", ["db.sqlite"]), [])

    def test_sqlite3_c_flag_wins_over_positionals(self):
        self.assertEqual(
            sql_verbs.sql_payloads("sqlite3", ["-c", "SELECT 1", "db.sqlite"]),
            ["SELECT 1"],
        )

    def test_duckdb_uses_c_rule(self):
        self.assertEqual(
            sql_verbs.sql_payloads("duckdb", ["db.duckdb", "-c", "SELECT 1"]),
            ["SELECT 1"],
        )

    # -- TK-57 REQ-02/REQ-03 -------------------------------------------

    def test_sqlite3_all_positionals_after_db_are_payload(self):
        # E-004: the prior "last positional only" rule missed an earlier
        # dangerous statement whose last positional happened to be RO.
        self.assertEqual(
            sql_verbs.sql_payloads(
                "sqlite3", ["db", "DROP TABLE t", "SELECT 1"]
            ),
            ["DROP TABLE t", "SELECT 1"],
        )

    def test_duckdb_all_positionals_after_db_are_payload(self):
        # duckdb docs confirm positional SQL execution the same as
        # sqlite3 (source in sql_verbs.sql_payloads docstring).
        self.assertEqual(
            sql_verbs.sql_payloads(
                "duckdb", ["db.duckdb", "DROP TABLE t", "SELECT 1"]
            ),
            ["DROP TABLE t", "SELECT 1"],
        )

    def test_sqlite3_value_flag_value_not_a_positional(self):
        # REQ-03: a non-SQL value-flag's value is neither payload nor a
        # SQL positional - the DROP stays the only classified statement
        # (E-004's exact command).
        self.assertEqual(
            sql_verbs.sql_payloads(
                "sqlite3",
                ["db", "DROP TABLE t", "-separator", "SELECT 1"],
            ),
            ["DROP TABLE t"],
        )
        self.assertEqual(
            sql_verbs.sql_payloads(
                "sqlite3", ["-separator", ",", "db", "select 1"]
            ),
            ["select 1"],
        )

    def test_sqlite3_two_token_value_flags_skipped(self):
        # -lookaside/-pagecache consume TWO value tokens.
        self.assertEqual(
            sql_verbs.sql_payloads(
                "sqlite3",
                ["-lookaside", "100", "10", "db", "select 1"],
            ),
            ["select 1"],
        )

    def test_duckdb_value_flags_skipped(self):
        self.assertEqual(
            sql_verbs.sql_payloads(
                "duckdb", ["-storage-version", "v1.2", "db", "select 1"]
            ),
            ["select 1"],
        )

    def test_mode_flags_yield_non_ro_marker_payload(self):
        for head, argv in (
            ("sqlite3", ["-A", "-x", "a.sar", "SELECT"]),
            ("sqlite3", ["--A", "-x", "a.sar", "SELECT"]),
            ("sqlite3", ["-Ax", "a.sar", "SELECT"]),
            ("sqlite3", ["-append", "db", "select 1"]),
            ("sqlite3", ["--append", "db", "select 1"]),
            ("sqlite3", ["-zip", "a.zip", "select 1"]),
            ("sqlite3", ["-unsafe-testing", "db", "select 1"]),
            ("sqlite3", ["-nonce", "STR", "db", "select 1"]),
            ("sqlite3", ["-init", "boot.sql", "db", "select 1"]),
            ("sqlite3", ["--init", "boot.sql", "db", "select 1"]),
            ("sqlite3", ["--init=boot.sql", "db", "select 1"]),
            ("duckdb", ["-unsigned", "db", "select 1"]),
            ("duckdb", ["-append", "db", "select 1"]),
        ):
            with self.subTest(head=head, argv=argv):
                payloads = sql_verbs.sql_payloads(head, argv)
                self.assertTrue(payloads, (head, argv))
                self.assertTrue(
                    any(
                        sql_verbs.classify_payload(p) != "ro"
                        for p in payloads
                    ),
                    (head, argv, payloads),
                )

    # -- TK-57 REQ-08 (gate closure): -cmd/--cmd/-cmd=/--cmd= ------------

    def test_cmd_flag_all_four_spellings_are_one_payload_flag(self):
        # E-001/E-009: `sqlite3 --cmd='PRAGMA user_version=123' 'SELECT 1'
        # 'SELECT 2'` was previously allowed because only bare single-dash
        # `-cmd` was recognized; all four spellings must yield the exact
        # same payload list.
        for head in ("sqlite3", "duckdb"):
            for flag in ("-cmd", "--cmd"):
                with self.subTest(head=head, form="bare", flag=flag):
                    self.assertEqual(
                        sql_verbs.sql_payloads(
                            head,
                            [flag, "PRAGMA user_version=123",
                             "SELECT 1", "SELECT 2"],
                        ),
                        ["PRAGMA user_version=123", "SELECT 2"],
                    )
            for flag_eq in ("-cmd=", "--cmd="):
                with self.subTest(head=head, form="attached", flag=flag_eq):
                    self.assertEqual(
                        sql_verbs.sql_payloads(
                            head,
                            [flag_eq + "PRAGMA user_version=123",
                             "SELECT 1", "SELECT 2"],
                        ),
                        ["PRAGMA user_version=123", "SELECT 2"],
                    )

    def test_cmd_flag_exact_e009_case(self):
        # Literal pin from the plan (REQ-08).
        self.assertEqual(
            sql_verbs.sql_payloads(
                "sqlite3",
                ["--cmd=PRAGMA user_version=123", "SELECT 1", "SELECT 2"],
            ),
            ["PRAGMA user_version=123", "SELECT 2"],
        )

    def test_cmd_flag_lookalike_is_not_matched(self):
        # `-cmdx`/`--cmdfoo` are not the cmd flag: ordinary unknown flag,
        # value token stays a plain positional.
        self.assertEqual(
            sql_verbs.sql_payloads(
                "sqlite3", ["-cmdx=PRAGMA user_version=123", "db", "select 1"]
            ),
            ["select 1"],
        )

    def test_mode_flag_lookalikes_are_not_markers(self):
        # -ascii starts with lowercase "a": not the -A archive family; not
        # in the mode-flag name set either -> ordinary unknown flag.
        self.assertEqual(
            sql_verbs.sql_payloads("sqlite3", ["-ascii", "db", "select 1"]),
            ["select 1"],
        )
        # -nullvalue is a plain value-flag, not a mode flag.
        self.assertEqual(
            sql_verbs.sql_payloads(
                "sqlite3", ["-nullvalue", "N/A", "db", "select 1"]
            ),
            ["select 1"],
        )


if __name__ == "__main__":
    unittest.main()
