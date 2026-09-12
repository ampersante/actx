import unittest

from actx_lib import hang_policy

NEVER_WRAP = "never_wrap"
GENEROUS = "generous"
DEFAULT = "default"


class TailTests(unittest.TestCase):
    def test_tail_f_is_never_wrap(self):
        self.assertEqual(hang_policy.classify(["tail", "-f", "x"]), NEVER_WRAP)

    def test_tail_long_follow_is_never_wrap(self):
        self.assertEqual(hang_policy.classify(["tail", "--follow", "x"]), NEVER_WRAP)

    def test_tail_follow_equals_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["tail", "--follow=name", "x"]), NEVER_WRAP
        )

    def test_tail_without_f_is_default(self):
        self.assertEqual(hang_policy.classify(["tail", "-n", "5", "f"]), DEFAULT)

    def test_bare_tail_is_default(self):
        self.assertEqual(hang_policy.classify(["tail"]), DEFAULT)


class KubectlTests(unittest.TestCase):
    def test_logs_f_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["kubectl", "logs", "-f", "pod"]), NEVER_WRAP
        )

    def test_flags_before_subcommand_are_allowed(self):
        self.assertEqual(
            hang_policy.classify(["kubectl", "-n", "ns", "logs", "-f", "pod"]),
            NEVER_WRAP,
        )

    def test_logs_long_follow_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["kubectl", "logs", "--follow", "pod"]), NEVER_WRAP
        )

    def test_plain_logs_is_default(self):
        self.assertEqual(hang_policy.classify(["kubectl", "logs", "pod"]), DEFAULT)

    def test_port_forward_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["kubectl", "port-forward", "pod", "8080"]),
            NEVER_WRAP,
        )

    def test_attach_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["kubectl", "attach", "pod"]), NEVER_WRAP
        )

    def test_get_is_default(self):
        self.assertEqual(hang_policy.classify(["kubectl", "get", "pods"]), DEFAULT)


class DockerTests(unittest.TestCase):
    def test_logs_f_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["docker", "logs", "-f", "c"]), NEVER_WRAP
        )

    def test_plain_logs_is_default(self):
        self.assertEqual(hang_policy.classify(["docker", "logs", "c"]), DEFAULT)

    def test_stats_without_no_stream_is_never_wrap(self):
        self.assertEqual(hang_policy.classify(["docker", "stats"]), NEVER_WRAP)

    def test_stats_no_stream_is_default(self):
        self.assertEqual(
            hang_policy.classify(["docker", "stats", "--no-stream"]), DEFAULT
        )

    def test_compose_up_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "up"]), NEVER_WRAP
        )

    def test_compose_up_detached_is_not_never_wrap(self):
        # TK-41 (H-F12): detached compose up is a long builder -> generous.
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "up", "-d"]), GENEROUS
        )

    def test_compose_up_detach_long_is_not_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "up", "--detach"]), GENEROUS
        )

    def test_compose_attach_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "attach", "x"]), NEVER_WRAP
        )

    def test_compose_up_behind_flags_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "-f", "stack.yml", "up"]),
            NEVER_WRAP,
        )
        self.assertEqual(
            hang_policy.classify(["docker", "--context", "x", "compose", "up"]),
            NEVER_WRAP,
        )

    def test_compose_up_detached_behind_flags_is_not_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(
                ["docker", "compose", "-f", "stack.yml", "up", "-d"]
            ),
            GENEROUS,
        )

    def test_compose_ps_is_default(self):
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "-f", "x.yml", "ps"]), DEFAULT
        )

    def test_compose_logs_f_is_never_wrap(self):
        # N-F5: RO ("compose","logs") would hang the wrapper for 600 s
        # without this guard.
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "logs", "-f"]), NEVER_WRAP
        )

    def test_compose_logs_follow_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "logs", "--follow", "web"]),
            NEVER_WRAP,
        )

    def test_plain_compose_logs_is_default(self):
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "logs"]), DEFAULT
        )
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "logs", "web"]), DEFAULT
        )

    def test_compose_file_flag_before_logs_is_not_follow(self):
        # `-f x.yml` is a compose-level FILE flag: must not read as follow.
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "-f", "x.yml", "logs"]),
            DEFAULT,
        )

    def test_detached_compose_up_is_generous(self):
        # H-F12: detached compose runs are long builders, not default.
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "up", "-d"]), GENEROUS
        )
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "up", "--detach"]), GENEROUS
        )
        self.assertEqual(
            hang_policy.classify(
                ["docker", "compose", "-f", "x.yml", "up", "-d"]
            ),
            GENEROUS,
        )
        self.assertEqual(
            hang_policy.classify(
                ["docker", "--context", "prod", "compose", "up", "-d"]
            ),
            GENEROUS,
        )

    def test_compose_build_is_generous(self):
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "build"]), GENEROUS
        )
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "-f", "x.yml", "build"]),
            GENEROUS,
        )

    def test_attach_is_never_wrap(self):
        self.assertEqual(hang_policy.classify(["docker", "attach", "c"]), NEVER_WRAP)

    def test_ps_is_default(self):
        self.assertEqual(hang_policy.classify(["docker", "ps"]), DEFAULT)


class WranglerAndRedisTests(unittest.TestCase):
    def test_wrangler_tail_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["wrangler", "tail"]), NEVER_WRAP
        )

    def test_redis_cli_monitor_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["redis-cli", "MONITOR"]), NEVER_WRAP
        )

    def test_redis_cli_monitor_is_case_insensitive(self):
        self.assertEqual(
            hang_policy.classify(["redis-cli", "monitor"]), NEVER_WRAP
        )

    def test_redis_cli_get_is_never_wrap(self):
        # TK-43 (Q2 wave-1 rule): GET prints raw VALUES - pattern redaction
        # cannot catch them, so never-wrap (exit 125). TK-52 reviews the
        # reverse. Pinned change from the pre-TK-43 "default".
        self.assertEqual(
            hang_policy.classify(["redis-cli", "GET", "k"]), NEVER_WRAP
        )


class GhTests(unittest.TestCase):
    """TK-55 (F2): gh stream_specs route through _is_cloud_stream."""

    def test_run_watch_is_never_wrap(self):
        # `gh run watch` waits on remote state -> never-wrap (exit 125).
        self.assertEqual(
            hang_policy.classify(["gh", "run", "watch"]), NEVER_WRAP
        )

    def test_pr_checks_watch_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["gh", "pr", "checks", "--watch"]),
            NEVER_WRAP,
        )
        # Acceptance finding: the positional PR number sits between the
        # verb and --watch — the dedicated _is_gh predicate covers it
        # (prefix stream_specs cannot).
        self.assertEqual(
            hang_policy.classify(["gh", "pr", "checks", "123", "--watch"]),
            NEVER_WRAP,
        )
        self.assertEqual(
            hang_policy.classify(["gh", "pr", "checks", "123", "-w"]),
            DEFAULT,
        )

    def test_non_streaming_verbs_are_default(self):
        for argv in (
            ["gh", "pr", "checks"],
            ["gh", "pr", "list"],
            ["gh", "run", "view"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), DEFAULT)


class JestVitestWatchTests(unittest.TestCase):
    """TK-55: watch modes on rewritten test runners -> never_wrap."""

    def test_watch_forms_are_never_wrap(self):
        for argv in (
            ["jest", "--watch"],
            ["jest", "--watchAll"],
            ["vitest"],                    # bare vitest is watch mode
            ["vitest", "watch"],
            ["vitest", "--watch"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), NEVER_WRAP)

    def test_run_forms_are_default(self):
        for argv in (
            ["jest"],
            ["jest", "--ci"],
            ["vitest", "run"],
            ["vitest", "run", "--reporter=dot"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), DEFAULT)


class WatchFuzzDebugTests(unittest.TestCase):
    """TK-55: watch/fuzz/debugger-attach flags on rewritten heads."""

    def test_never_wrap(self):
        for argv in (
            ["tsc", "--watch"],
            ["tsc", "-w"],
            ["tsc", "--build", "--watch"],
            ["ruff", "check", "--watch", "."],
            ["go", "test", "-fuzz=FuzzX", "."],
            ["go", "test", "-test.fuzz=FuzzX", "."],
            ["vitest", "run", "--inspect-brk"],
            ["vitest", "run", "--api"],
            ["vitest", "run", "--browser.name=chrome"],
            ["pytest", "--pdb"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), NEVER_WRAP)

    def test_default(self):
        for argv in (
            ["tsc", "--noEmit"],
            ["ruff", "check", "."],
            ["vitest", "run"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), DEFAULT)
        # `go test`/`pytest` are _LONG_OPS heads -> generous; an inert
        # -fuzztime alone is not never_wrap.
        for argv in (
            ["go", "test", "-fuzztime=10s", "."],
            ["pytest", "-q"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), "generous")


class FlutterTests(unittest.TestCase):
    def test_run_is_never_wrap(self):
        self.assertEqual(hang_policy.classify(["flutter", "run"]), NEVER_WRAP)

    def test_attach_is_never_wrap(self):
        self.assertEqual(hang_policy.classify(["flutter", "attach"]), NEVER_WRAP)

    def test_logs_is_never_wrap(self):
        self.assertEqual(hang_policy.classify(["flutter", "logs"]), NEVER_WRAP)

    def test_emulators_launch_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["flutter", "emulators", "--launch"]), NEVER_WRAP
        )

    def test_emulators_launch_name_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["flutter", "emulators", "--launch", "pixel"]),
            NEVER_WRAP,
        )

    def test_emulators_list_is_default(self):
        self.assertEqual(
            hang_policy.classify(["flutter", "emulators"]), DEFAULT
        )

    def test_doctor_android_licenses_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["flutter", "doctor", "--android-licenses"]),
            NEVER_WRAP,
        )

    def test_doctor_is_default(self):
        self.assertEqual(hang_policy.classify(["flutter", "doctor"]), DEFAULT)


class MobileHangPolicyTests(unittest.TestCase):
    """TK-42: flutter/dart/swift/xcodebuild/pod/gradlew hang classes."""

    def test_flutter_stream_subs_are_never_wrap(self):
        for argv in (
            ["flutter", "run"],
            ["flutter", "attach"],
            ["flutter", "logs"],
            ["flutter", "channel"],
            ["flutter", "channel", "stable"],
            ["flutter", "upgrade"],
            ["flutter", "downgrade"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), NEVER_WRAP)

    def test_swift_repl_and_run_are_never_wrap(self):
        self.assertEqual(hang_policy.classify(["swift", "repl"]), NEVER_WRAP)
        self.assertEqual(hang_policy.classify(["swift", "run", "App"]), NEVER_WRAP)

    def test_xcodebuild_interactive_is_never_wrap(self):
        for argv in (
            ["xcodebuild"],
            ["xcodebuild", "-allowProvisioningUpdates", "-scheme", "App", "build"],
            ["xcodebuild", "build"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), NEVER_WRAP)

    def test_mobile_long_ops_are_generous(self):
        for argv in (
            ["flutter", "build", "apk"],
            ["flutter", "test"],
            ["flutter", "pub", "get"],
            ["dart", "test"],
            ["dart", "pub", "get"],
            ["swift", "build"],
            ["swift", "test"],
            ["pod", "install"],
            ["./gradlew", "build"],
            ["./gradlew"],
            ["xcodebuild", "-scheme", "App"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), GENEROUS)

    def test_mobile_ro_commands_are_default(self):
        for argv in (
            ["flutter", "doctor"],
            ["flutter", "analyze"],
            ["dart", "analyze"],
            ["swiftlint", "lint"],
            ["pod", "outdated"],
            ["pod", "list"],
            ["xcrun", "simctl", "list", "devices"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), DEFAULT)


class LoginTests(unittest.TestCase):
    def test_login_heads_are_never_wrap(self):
        for head in (
            "wrangler", "railway", "gcloud", "vercel", "netlify",
            "supabase", "flyctl", "fly",
        ):
            with self.subTest(head=head):
                self.assertEqual(
                    hang_policy.classify([head, "login"]), NEVER_WRAP
                )

    def test_gcloud_auth_login_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["gcloud", "auth", "login"]), NEVER_WRAP
        )

    def test_other_subcommand_is_default(self):
        self.assertEqual(
            hang_policy.classify(["gcloud", "auth", "list"]), DEFAULT
        )


class ReplTests(unittest.TestCase):
    def test_bare_repls_are_never_wrap(self):
        for head in ("psql", "sqlite3", "duckdb", "mongosh",
                     "snowsql", "databricks"):
            with self.subTest(head=head):
                self.assertEqual(hang_policy.classify([head]), NEVER_WRAP)

    def test_repl_with_nonflag_query_argument_is_never_wrap(self):
        self.assertEqual(hang_policy.classify(["psql", "mydb"]), NEVER_WRAP)
        self.assertEqual(hang_policy.classify(["mongosh", "file.js"]), NEVER_WRAP)
        self.assertEqual(
            hang_policy.classify(["snowsql", "-d", "mydb"]), NEVER_WRAP
        )

    def test_sqlite3_batch_form_is_not_a_repl(self):
        # Red-gate 17 (H-F3/N-F6, TK-43): db + SQL positionals run one
        # batch and exit - the rewrite path owns them now. Pinned change
        # from the pre-TK-43 never-wrap.
        self.assertEqual(
            hang_policy.classify(["sqlite3", "db.sqlite", "SELECT 1"]),
            DEFAULT,
        )
        self.assertEqual(
            hang_policy.classify(["sqlite3", "db.sqlite", ".tables"]),
            DEFAULT,
        )
        # Bare db (1 positional) is still the interactive REPL.
        self.assertEqual(
            hang_policy.classify(["sqlite3", "db.sqlite"]), NEVER_WRAP
        )

    def test_repl_with_c_flag_is_default(self):
        self.assertEqual(
            hang_policy.classify(["psql", "-c", "select 1"]), DEFAULT
        )
        self.assertEqual(
            hang_policy.classify(["sqlite3", "db.sqlite", "-c", "SELECT 1"]),
            DEFAULT,
        )

    def test_swift_repl_is_never_wrap(self):
        self.assertEqual(hang_policy.classify(["swift", "repl"]), NEVER_WRAP)

    def test_swift_repl_with_c_is_default(self):
        self.assertEqual(
            hang_policy.classify(["swift", "repl", "-c", "print(1)"]), DEFAULT
        )

    def test_swift_run_is_never_wrap(self):
        # TK-42: launches the built executable (interactive).
        self.assertEqual(hang_policy.classify(["swift", "run"]), NEVER_WRAP)
        self.assertEqual(
            hang_policy.classify(["swift", "run", "App"]), NEVER_WRAP
        )

    def test_swift_other_subcommand_is_default(self):
        self.assertEqual(
            hang_policy.classify(["swift", "package", "dump-package"]), DEFAULT
        )


class GenerousTests(unittest.TestCase):
    def test_long_ops_are_generous(self):
        cases = (
            ["flutter", "build", "apk"],
            ["xcodebuild", "-scheme", "App", "build"],
            ["cargo", "build"],
            ["go", "build", "./..."],
            ["npm", "install"],
            ["npm", "ci"],
            ["pnpm", "install"],
            ["pnpm", "ci"],
            ["pip", "install", "requests"],
            ["uv", "pip", "install", "x"],
            ["docker", "build", "."],
            ["pytest"],
            ["cargo", "test"],
            ["go", "test", "./..."],
            # Data stack (TK-43): long builders.
            ["terraform", "plan"],
            ["terraform", "plan", "-out", "tfplan"],
            ["dbt", "run"],
            ["dbt", "test"],
            ["dbt", "build"],
        )
        for argv in cases:
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), GENEROUS)

    def test_unrelated_commands_are_default(self):
        for argv in (["git", "status"], ["ls"], ["docker", "ps"], ["go", "fmt"]):
            self.assertEqual(hang_policy.classify(argv), DEFAULT)


class EdgeCaseTests(unittest.TestCase):
    def test_empty_argv_is_default(self):
        self.assertEqual(hang_policy.classify([]), DEFAULT)

    def test_single_token_heads(self):
        # TK-42: bare xcodebuild builds the default scheme with interactive
        # signing - never-wrap (pinned change from the previous generous).
        self.assertEqual(hang_policy.classify(["xcodebuild"]), NEVER_WRAP)
        self.assertEqual(hang_policy.classify(["pytest"]), GENEROUS)
        self.assertEqual(hang_policy.classify(["psql"]), NEVER_WRAP)


class InteractivePromptTests(unittest.TestCase):
    def test_known_patterns_detected(self):
        for text in (
            "Proceed? [y/n] ",
            "Overwrite? [Y/n] ",
            "Continue? [Y/N]",
            "Do you want to continue? (yes/no)",
            "Proceed?",
            "Continue?",
            "Press any key to continue",
        ):
            with self.subTest(text=text):
                self.assertTrue(hang_policy.is_interactive_prompt(text))

    def test_plain_output_not_detected(self):
        for text in ("", None, "all tests passed", "3 files changed"):
            self.assertFalse(hang_policy.is_interactive_prompt(text))

    def test_detection_is_case_insensitive(self):
        self.assertTrue(hang_policy.is_interactive_prompt("press ANY key"))


if __name__ == "__main__":
    unittest.main()
