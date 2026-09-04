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
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "up", "-d"]), DEFAULT
        )

    def test_compose_up_detach_long_is_not_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "up", "--detach"]), DEFAULT
        )

    def test_compose_attach_is_never_wrap(self):
        self.assertEqual(
            hang_policy.classify(["docker", "compose", "attach", "x"]), NEVER_WRAP
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

    def test_redis_cli_get_is_default(self):
        self.assertEqual(
            hang_policy.classify(["redis-cli", "GET", "k"]), DEFAULT
        )


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
        for head in ("psql", "sqlite3", "duckdb", "mongosh"):
            with self.subTest(head=head):
                self.assertEqual(hang_policy.classify([head]), NEVER_WRAP)

    def test_repl_with_nonflag_query_argument_is_never_wrap(self):
        self.assertEqual(hang_policy.classify(["psql", "mydb"]), NEVER_WRAP)
        self.assertEqual(
            hang_policy.classify(["sqlite3", "db.sqlite", "SELECT 1"]), NEVER_WRAP
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

    def test_swift_other_subcommand_is_default(self):
        self.assertEqual(hang_policy.classify(["swift", "run"]), DEFAULT)


class GenerousTests(unittest.TestCase):
    def test_long_ops_are_generous(self):
        cases = (
            ["flutter", "build", "apk"],
            ["xcodebuild"],
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
        self.assertEqual(hang_policy.classify(["xcodebuild"]), GENEROUS)
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
