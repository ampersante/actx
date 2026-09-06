import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest

from actx_lib import conventions, tracking

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")

TS1 = 1700000000
NOW = int(time.time())


class InsightsTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.work = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.home.cleanup()
        self.work.cleanup()

    def run_actx(self, *args):
        env = os.environ.copy()
        env["HOME"] = self.home.name
        return subprocess.run(
            [ACTX] + list(args),
            capture_output=True,
            text=True,
            cwd=self.work.name,
            env=env,
        )

    def seed(self, rows):
        os.environ["HOME"] = self.home.name
        try:
            conn = tracking.connect()
            for category, before, after, code, timestamp, passthrough in rows:
                command_hash = hashlib.sha1(
                    ("cmd %s" % category).encode("utf-8")
                ).hexdigest()
                conn.execute(
                    "INSERT INTO calls (command_hash, category, bytes_before, "
                    "bytes_after, exit_code, timestamp, passthrough) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        command_hash,
                        category,
                        before,
                        after,
                        code,
                        timestamp,
                        passthrough,
                    ),
                )
            conn.commit()
            conn.close()
        finally:
            del os.environ["HOME"]

    def seed_with_text(self, rows):
        os.environ["HOME"] = self.home.name
        try:
            conn = tracking.connect()
            for text, category, before, after, code, timestamp, passthrough in rows:
                command_hash = hashlib.sha1(text.encode("utf-8")).hexdigest()
                conn.execute(
                    "INSERT INTO calls (command_hash, command_text, category, "
                    "bytes_before, bytes_after, exit_code, timestamp, passthrough) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        command_hash,
                        text,
                        category,
                        before,
                        after,
                        code,
                        timestamp,
                        passthrough,
                    ),
                )
            conn.commit()
            conn.close()
        finally:
            del os.environ["HOME"]

    def test_discover_sorted_by_passthrough_frequency(self):
        self.seed(
            [
                ("docker", 5, 5, 0, TS1, 1),
                ("docker", 5, 5, 0, TS1, 1),
                ("docker", 5, 5, 0, TS1, 1),
                ("gh", 5, 5, 0, TS1, 1),
                ("gh", 5, 5, 0, TS1, 1),
                ("git", 5, 5, 0, TS1, 1),
                ("git", 20, 10, 0, TS1, 0),
            ]
        )
        p = self.run_actx("discover")
        self.assertEqual(p.returncode, 0)
        lines = p.stdout.strip().split("\n")
        self.assertEqual(lines, ["docker", "gh", "git"])

    def test_session_adoption(self):
        self.seed(
            [
                ("git", 20, 10, 0, TS1, 0),
                ("docker", 5, 5, 0, TS1 + 1000, 1),
                ("git", 30, 10, 0, TS1 + 100000, 0),
                ("run", 40, 20, 0, TS1 + 101000, 0),
            ]
        )
        p = self.run_actx("session")
        self.assertEqual(p.returncode, 0)
        self.assertIn("adoption: 50.0%", p.stdout)
        self.assertIn("adoption: 100.0%", p.stdout)

    def test_mismatched_schema_exit_zero(self):
        os.environ["HOME"] = self.home.name
        try:
            conn = tracking.connect()
            conn.execute("DROP TABLE IF EXISTS calls")
            conn.execute("CREATE TABLE calls (id INTEGER)")
            conn.commit()
            conn.close()
        finally:
            del os.environ["HOME"]
        for command in ("discover", "session"):
            p = self.run_actx(command)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(p.stdout, "")

    def test_empty_database_exit_zero(self):
        for command in ("discover", "session"):
            p = self.run_actx(command)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(p.stdout, "")


    def test_insights_shows_sections_and_suggestions(self):
        self.seed_with_text(
            [
                ("git status", "git", 100, 50, 0, NOW, 0),
                ("git status", "git", 100, 50, 0, NOW, 0),
                ("git status", "git", 100, 50, 0, NOW, 0),
                ("git log", "git", 2000, 100, 0, NOW, 0),
                ("pytest x", "pytest", 5000, 500, 1, NOW, 0),
                ("pytest x", "pytest", 5000, 500, 1, NOW, 0),
                ("docker ps", "docker", 300, 300, 0, NOW, 1),
                ("cat f.txt", "cat", 20, 20, 0, NOW, 0),
                ("cat f.txt", "cat", 20, 20, 0, NOW, 0),
                ("cat f.txt", "cat", 20, 20, 0, NOW, 0),
            ]
        )
        p = self.run_actx("insights")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("repeated:", p.stdout)
        self.assertIn("3 calls", p.stdout)
        self.assertIn("failing:", p.stdout)
        self.assertIn("2 failures", p.stdout)
        self.assertIn("passthrough:", p.stdout)
        self.assertIn("docker ps", p.stdout)
        self.assertIn("git log без -n", p.stdout)
        self.assertIn("файл читается 3 раз", p.stdout)

    def test_insights_json_valid(self):
        self.seed_with_text([("git status", "git", 100, 50, 0, NOW, 0)])
        p = self.run_actx("insights", "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["repeated"][0]["command"], "git status")
        self.assertEqual(data["repeated"][0]["calls"], 1)

    def test_insights_old_db_migrates(self):
        os.environ["HOME"] = self.home.name
        try:
            conn = tracking.connect()
            conn.execute("DROP TABLE IF EXISTS calls")
            conn.execute(
                "CREATE TABLE calls ("
                "command_hash TEXT, category TEXT, bytes_before INTEGER, "
                "bytes_after INTEGER, exit_code INTEGER, timestamp INTEGER, "
                "passthrough INTEGER)"
            )
            conn.execute(
                "INSERT INTO calls (command_hash, category, bytes_before, "
                "bytes_after, exit_code, timestamp, passthrough) "
                "VALUES ('h', 'git', 1, 1, 0, ?, 0)",
                (TS1,),
            )
            conn.commit()
            conn.close()
        finally:
            del os.environ["HOME"]
        p = self.run_actx("insights")
        self.assertEqual(p.returncode, 0)

    # --- TK-46: wave-1/2 heads synthetic history (adoption + verbose) ---
    def seed_wave_history(self):
        """kubectl compressed+passthrough; flutter compressed; dbt 3 rows
        exit 124/125 + 1 compressed (adoption must be 1/1 = 100%, not 25%);
        psql passthrough; git passthrough - a wave-0 head that must stay
        out of the adoption report (WAVE_HEADS is the only filter)."""
        self.seed_with_text(
            [
                ("kubectl get pods", "kubectl", 8000, 200, 0, NOW, 0),
                ("kubectl describe svc x", "kubectl", 4000, 4000, 0, NOW, 1),
                ("flutter test x", "flutter", 500, 100, 0, NOW, 0),
                ("dbt run", "dbt", 10, 10, 124, NOW, 1),
                ("dbt run", "dbt", 10, 10, 125, NOW, 1),
                ("dbt run", "dbt", 10, 10, 124, NOW, 1),
                ("dbt run --select m", "dbt", 1000, 100, 0, NOW, 0),
                ("psql -c 'SELECT'", "psql", 3000, 3000, 0, NOW, 1),
                ("git log", "git", 9000, 9000, 0, NOW, 1),
            ]
        )

    def test_adoption_report_text(self):
        # G3: adoption on WAVE_HEADS; N-F1 coverage gate - flutter/dbt/
        # kubectl present (the degenerate REGISTRY&FAMILIES set would drop
        # them); git out (not a wave-1/2 head); dbt 100% not 25% (H-F5/N-F6);
        # zero-call heads (helm and 22 others) never listed (W-F10).
        self.seed_wave_history()
        p = self.run_actx("insights")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("adoption:", p.stdout)
        self.assertIn("kubectl: 2 calls, 1 compressed, 50%", p.stdout)
        self.assertIn("flutter: 1 calls, 1 compressed, 100%", p.stdout)
        self.assertIn("dbt: 1 calls, 1 compressed, 100%", p.stdout)
        self.assertIn("psql: 1 calls, 0 compressed, 0%", p.stdout)
        self.assertIn("exits 124/125 excluded", p.stdout)
        self.assertNotIn("dbt: 4 calls", p.stdout)  # 124/125 not counted
        self.assertNotIn("dbt: 1 calls, 1 compressed, 25%", p.stdout)
        self.assertNotIn("git: ", p.stdout)  # wave-0 head, not in WAVE_HEADS
        self.assertNotIn("helm: ", p.stdout)  # zero observed calls -> omitted
        # sort: calls DESC (kubectl 2 first, then the four 1-call heads)
        kubectl = p.stdout.index("kubectl: 2 calls")
        flutter = p.stdout.index("flutter: 1 calls")
        dbt = p.stdout.index("dbt: 1 calls")
        self.assertLess(kubectl, flutter)
        self.assertLess(kubectl, dbt)

    def test_adoption_report_json(self):
        self.seed_wave_history()
        p = self.run_actx("insights", "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertIn("adoption", data)
        by_head = {row["head"]: row for row in data["adoption"]}
        # N-F1 gate in the JSON form too: the mobile/SQL heads survive.
        self.assertIn("flutter", by_head)
        self.assertIn("dbt", by_head)
        self.assertIn("kubectl", by_head)
        self.assertNotIn("git", by_head)
        self.assertNotIn("helm", by_head)
        self.assertEqual(by_head["dbt"]["calls"], 1)
        self.assertEqual(by_head["dbt"]["compressed"], 1)
        self.assertEqual(by_head["dbt"]["adoption_pct"], 100.0)
        self.assertEqual(by_head["kubectl"]["calls"], 2)
        self.assertEqual(by_head["kubectl"]["adoption_pct"], 50.0)
        # calls DESC, ties by head ASC
        self.assertEqual(
            [row["head"] for row in data["adoption"]],
            ["kubectl", "dbt", "flutter", "psql"],
        )

    def test_verbose_commands_text_order_and_suggestions(self):
        # G3 + Red-5: --verbose-commands parses; heads only (never
        # command_text - REQ-05b); raw_bytes DESC; suggested straight from
        # CONVENTIONS, null-ish for a head with no record.
        self.seed_wave_history()
        p = self.run_actx("insights", "--verbose-commands")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("verbose_commands:", p.stdout)
        git = p.stdout.index("git  1 calls  9000 raw bytes")
        psql = p.stdout.index("psql  1 calls  3000 raw bytes")
        kubectl = p.stdout.index("kubectl  1 calls  4000 raw bytes")
        dbt = p.stdout.index("dbt  3 calls  30 raw bytes")
        self.assertLess(git, kubectl)
        self.assertLess(kubectl, psql)
        self.assertLess(psql, dbt)
        # psql advice comes from the shared table (single source, REQ-01)
        self.assertIn(
            "psql  1 calls  3000 raw bytes  suggested: %s"
            % conventions.CONVENTIONS["psql"][0][2],
            p.stdout,
        )
        self.assertIn(
            "git  1 calls  9000 raw bytes  suggested: %s"
            % conventions.CONVENTIONS["git"][0][2],
            p.stdout,
        )
        # no command text in the new report
        self.assertNotIn("git log\n", p.stdout.split("verbose_commands:")[-1])
        # additive flag: the regular sections still print
        self.assertIn("repeated:", p.stdout)
        self.assertIn("suggestions:", p.stdout)

    def test_verbose_commands_json(self):
        self.seed_wave_history()
        p = self.run_actx("insights", "--verbose-commands", "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertIn("verbose_commands", data)
        rows = data["verbose_commands"]
        self.assertEqual(
            [row["head"] for row in rows],
            ["git", "kubectl", "psql", "dbt"],
        )
        by_head = {row["head"]: row for row in rows}
        self.assertEqual(by_head["git"]["calls"], 1)
        self.assertEqual(by_head["git"]["raw_bytes"], 9000)
        self.assertEqual(
            by_head["git"]["suggested"], conventions.CONVENTIONS["git"][0][2]
        )
        self.assertEqual(by_head["dbt"]["calls"], 3)
        self.assertEqual(by_head["dbt"]["raw_bytes"], 30)

    def test_verbose_commands_head_without_convention_suggested_none(self):
        # W-F11 discipline: a passthrough head absent from CONVENTIONS gets
        # no invented advice - JSON suggested is null.
        self.seed_with_text(
            [
                ("wrangler whoami", "wrangler", 5000, 5000, 0, NOW, 1),
                ("wrangler whoami", "wrangler", 2000, 2000, 0, NOW, 1),
            ]
        )
        p = self.run_actx("insights", "--verbose-commands", "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        rows = json.loads(p.stdout)["verbose_commands"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["head"], "wrangler")
        self.assertEqual(rows[0]["calls"], 2)
        self.assertEqual(rows[0]["raw_bytes"], 7000)
        self.assertIsNone(rows[0]["suggested"])
        pt = self.run_actx("insights", "--verbose-commands")
        self.assertIn("wrangler  2 calls  7000 raw bytes  suggested: none",
                      pt.stdout)

    def test_adoption_empty_db_exit_zero(self):
        # no history.db at all: empty adoption, exit 0 (fail-open precedent
        # of the surrounding empty-db tests).
        p = self.run_actx("insights")
        self.assertEqual(p.returncode, 0)
        self.assertIn("adoption:", p.stdout)
        self.assertIn("  none", p.stdout.split("adoption:")[-1])
        pj = self.run_actx("insights", "--json")
        self.assertEqual(pj.returncode, 0)
        self.assertEqual(json.loads(pj.stdout)["adoption"], [])

if __name__ == "__main__":
    unittest.main()
