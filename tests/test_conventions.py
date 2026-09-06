import unittest

from actx_lib import conventions


class HintForTests(unittest.TestCase):
    def test_git_log_without_n_hinted(self):
        advice = conventions.hint_for("git log")
        self.assertEqual(advice, "add -n N (e.g. git log -n 50 --oneline)")

    def test_git_log_with_n_not_hinted(self):
        self.assertIsNone(conventions.hint_for("git log -n 50 --oneline"))
        self.assertIsNone(conventions.hint_for("git log --max-count 50"))
        self.assertIsNone(conventions.hint_for("git log -n 5"))

    def test_git_login_not_matched_on_git_log(self):
        # A1: token matching, never a substring match.
        self.assertIsNone(conventions.hint_for("git login"))
        self.assertIsNone(conventions.hint_for("git logins"))

    def test_bare_git_status_no_hint(self):
        # test_hook.py:107 keeps its exact additionalContext text for
        # `git status` - the head has no hint-eligible record at all.
        self.assertIsNone(conventions.hint_for("git status"))
        self.assertIsNone(conventions.hint_for("git status --porcelain"))
        self.assertIsNone(conventions.hint_for("git diff"))
        self.assertIsNone(conventions.hint_for("git branch"))

    def test_flag_present_in_any_token_disables_hint(self):
        self.assertIsNone(conventions.hint_for("kubectl get pods -o json"))
        self.assertIsNone(conventions.hint_for("kubectl get pods --output wide"))
        self.assertIsNone(conventions.hint_for("kubectl -n prod get pods"))

    def test_missing_flag_gives_hint(self):
        self.assertIsNotNone(conventions.hint_for("kubectl get pods"))
        self.assertIsNotNone(conventions.hint_for("docker ps"))
        self.assertIsNotNone(conventions.hint_for("pytest tests/"))

    def test_unquoted_command_returns_none(self):
        self.assertIsNone(conventions.hint_for('git log "unclosed'))

    def test_unknown_head_returns_none(self):
        self.assertIsNone(conventions.hint_for("some-binary log"))
        self.assertIsNone(conventions.hint_for(""))

    def test_verb_prefix_must_match(self):
        # kubectl describe has its own record; kubectl top does not.
        self.assertEqual(
            conventions.hint_for("kubectl describe pod x"),
            "not every describe output compresses - prefer "
            "kubectl get -o json when scripting",
        )
        self.assertIsNone(conventions.hint_for("kubectl top nodes"))

    def test_gradlew_head_matched(self):
        self.assertIsNone(conventions.hint_for("./gradlew test"))

    def test_psql_sql_limit_advice(self):
        advice = conventions.hint_for('psql -c "SELECT * FROM users"')
        self.assertEqual(advice, "add LIMIT n to bound row output")
        # LIMIT already present -> no advice.
        self.assertIsNone(
            conventions.hint_for('psql -c "SELECT * FROM users LIMIT 10"')
        )

    def test_terraform_plan_no_color(self):
        self.assertEqual(
            conventions.hint_for("terraform plan"),
            "add -no-color to drop ANSI escapes",
        )
        self.assertIsNone(conventions.hint_for("terraform plan -no-color"))
        self.assertIsNone(conventions.hint_for("terraform validate"))

    def test_git_log_with_dash_n_prefix_variants(self):
        # `--max-count=50` is the single-token =-form: the flag is present,
        # no hint. `-n50` is a distinct token from `-n`: the hint still
        # fires - conservative, the advice remains accurate.
        self.assertIsNone(conventions.hint_for("git log --max-count=50"))
        self.assertIsNotNone(conventions.hint_for("git log -n50"))


class RenderTier2Tests(unittest.TestCase):
    def test_nonempty_and_bounded(self):
        text = conventions.render_tier2()
        self.assertTrue(text.strip())
        lines = text.splitlines()
        # Stop-trigger 4: the Tier-2 block stays <=30 content lines.
        self.assertLessEqual(len(lines), 30)
        self.assertGreaterEqual(len(lines), 5)

    def test_contains_header_and_key_conventions(self):
        text = conventions.render_tier2()
        self.assertIn("Prefer compact flags", text)
        for needle in (
            "git log -n 50",
            "--porcelain",
            "kubectl get -o json",
            "docker ps --format",
            "pytest -q",
            "flutter test --reporter compact",
            "xcodebuild -quiet",
            "LIMIT n",
            "bq --format=json",
            "terraform plan -no-color",
            "dbt run --select",
        ):
            self.assertIn(needle, text)

    def test_deterministic(self):
        self.assertEqual(conventions.render_tier2(), conventions.render_tier2())


class WaveHeadsTests(unittest.TestCase):
    def test_exact_size_26(self):
        self.assertEqual(len(conventions.WAVE_HEADS), 26)

    def test_cloud_infra_mobile_data_groups(self):
        self.assertEqual(
            conventions.WAVE_HEADS
            & {
                "vercel", "netlify", "railway", "wrangler", "supabase",
                "flyctl", "gcloud",
            },
            {"vercel", "netlify", "railway", "wrangler", "supabase",
             "flyctl", "gcloud"},
        )
        self.assertEqual(
            conventions.WAVE_HEADS & {"docker", "kubectl", "helm"},
            {"docker", "kubectl", "helm"},
        )
        self.assertEqual(
            conventions.WAVE_HEADS
            & {
                "flutter", "dart", "swift", "swiftlint", "swiftformat",
                "xcodebuild", "xcrun", "pod", "./gradlew",
            },
            {"flutter", "dart", "swift", "swiftlint", "swiftformat",
             "xcodebuild", "xcrun", "pod", "./gradlew"},
        )
        self.assertEqual(
            conventions.WAVE_HEADS
            & {
                "psql", "sqlite3", "duckdb", "bq", "terraform",
                "redis-cli", "dbt",
            },
            {"psql", "sqlite3", "duckdb", "bq", "terraform",
             "redis-cli", "dbt"},
        )

    def test_coverage_gate_heads_present(self):
        # N-F1: the set is a curated literal, not a FAMILIES intersection -
        # flutter/xcodebuild/psql/dbt/kubectl must survive (E-025).
        for head in ("flutter", "xcodebuild", "psql", "dbt", "kubectl"):
            self.assertIn(head, conventions.WAVE_HEADS)

    def test_is_frozenset(self):
        self.assertIsInstance(conventions.WAVE_HEADS, frozenset)


class DataShapeTests(unittest.TestCase):
    def test_entry_shape(self):
        for head, entries in conventions.CONVENTIONS.items():
            self.assertIsInstance(head, str)
            self.assertIsInstance(entries, tuple)
            self.assertTrue(entries, head)
            for entry in entries:
                self.assertEqual(len(entry), 4, (head, entry))
                verb_prefix, missing_flags, advice, tier2 = entry
                self.assertIsInstance(verb_prefix, tuple)
                self.assertIsInstance(missing_flags, tuple)
                self.assertTrue(missing_flags, (head, entry))
                self.assertIsInstance(advice, str)
                self.assertTrue(advice, (head, entry))
                self.assertIsInstance(tier2, bool)

    def test_no_lambdas_in_data(self):
        for entries in conventions.CONVENTIONS.values():
            for entry in entries:
                for field in entry[:3]:
                    self.assertFalse(callable(field), (entry, field))

    def test_tier2_entries_exist(self):
        self.assertTrue(
            any(entry[3] for entries in conventions.CONVENTIONS.values()
                for entry in entries)
        )


if __name__ == "__main__":
    unittest.main()
