"""TK-60 STEP-W5: executable pins for the closed-grammar engine
(actx_lib.rewrite_spec.HEAD_SPECS + actx_lib.rewriter's matcher).

Structure:
  - RewriteSpecPositiveTests: for a representative cross-section of heads
    (every head with non-trivial grammar - verb trees, hooks, forward
    specs, run-prefixes, plus a flat sample), every admitted spelling of
    every declared flag rewrites in a minimal command.
  - RewriteSpecGenericNegativeTests: the grammar-level negative rules that
    must hold for ANY head with the relevant feature - unknown flag,
    long-flag abbreviation, a cluster containing a value-flag's letter,
    an optional-value flag followed by an unknown flag, a required-value
    flag followed by a token starting with "-".
  - RewriteSpecPlanPinTests: the plan's own explicit STEP-W5 negative pins
    (cargo test --/go test -args forwarding) plus the TK-57 finding pins
    (E-001) that must stay fixed under the new engine.

Not exhaustive over all 53 heads (the corpus/replay tooling is the
completeness mechanism, per STEP-W1/W4) - this file pins the GRAMMAR
primitives and the specific commands the plan names by exact text."""
import unittest

from actx_lib.rewriter import rewrite


class RewriteSpecPositiveTests(unittest.TestCase):
    def assert_rewrites(self, command):
        self.assertEqual(rewrite(command), "actx " + command, command)

    def assert_not_rewritten(self, command):
        self.assertIsNone(rewrite(command), command)

    # --- git (verb tree, inherit=False, numeric, optional, cluster) ---
    def test_git_status_flags(self):
        for command in ("git status", "git status -s", "git status --short",
                         "git status -sb", "git status --porcelain",
                         "git status --porcelain=2", "git status -- x"):
            self.assert_rewrites(command)

    def test_git_log_diff_show_flags(self):
        for command in ("git log --oneline", "git log -n 50 --oneline",
                         "git log -5", "git diff --stat", "git diff -U0",
                         "git diff --check", "git diff -- file.py",
                         "git show HEAD", "git show --stat HEAD"):
            self.assert_rewrites(command)

    def test_git_mutators(self):
        for command in ("git add .", 'git commit -m "msg"',
                         "git push origin main", "git push --force origin main",
                         "git pull --rebase", "git fetch"):
            self.assert_rewrites(command)

    def test_git_branch_stash(self):
        self.assert_rewrites("git branch -a")
        self.assert_rewrites("git stash list")
        self.assert_not_rewritten("git stash")
        self.assert_not_rewritten("git branch feature-x")

    # --- SQL heads (hook="sql_payload", quote guard in rewrite()) ---
    def test_sql_heads(self):
        self.assert_rewrites('psql -c "SELECT 1"')
        self.assert_rewrites("sqlite3 db.sqlite \"SELECT 1\"")
        self.assert_rewrites('duckdb -c "SELECT 1;"')

    def test_sql_dangerous_payload_rejected(self):
        self.assert_not_rewritten('psql -c "DROP TABLE x"')
        self.assert_not_rewritten("sqlite3 db.sqlite 'DROP TABLE t' 'SELECT 1'")

    # --- cargo (root hook, verb tree, forward specs) ---
    def test_cargo_toolchain_and_verbs(self):
        self.assert_rewrites("cargo +nightly fmt --check")
        self.assert_rewrites("cargo check")
        self.assert_rewrites("cargo test")
        self.assert_rewrites("cargo fmt --check")
        self.assert_rewrites("cargo fmt -- --check")
        self.assert_rewrites("cargo clippy -- -D warnings")
        self.assert_rewrites("cargo metadata --no-deps")
        self.assert_rewrites("cargo package --list")

    def test_cargo_required_flag_missing_rejected(self):
        self.assert_not_rewritten("cargo fmt")
        self.assert_not_rewritten("cargo metadata")
        self.assert_not_rewritten("cargo package")

    # --- go (dashdash_literals=-args, after_dashdash=forbid) ---
    def test_go_test_flags(self):
        self.assert_rewrites("go test ./...")
        self.assert_rewrites("go test --count=1 ./...")
        self.assert_rewrites("go test -run X ./...")

    # --- ./gradlew (hook="gradle_task" per positional) ---
    def test_gradlew(self):
        self.assert_rewrites("./gradlew test")
        self.assert_rewrites("./gradlew build --parallel")
        self.assert_rewrites("./gradlew :app:assembleDebug")

    def test_gradlew_ask_class_rejected(self):
        self.assert_not_rewritten("./gradlew publish")
        self.assert_not_rewritten("./gradlew clean")

    # --- run-prefixes (REQ-07: inner head validated against its own spec) ---
    def test_run_prefix_inner_head_validated(self):
        self.assert_rewrites("uv run pytest")
        self.assert_rewrites("xcrun simctl list")
        self.assert_not_rewritten("uv run rm -rf ~")
        self.assert_not_rewritten("uv run tsc --outFile /tmp/x")
        self.assert_not_rewritten("xcrun simctl erase udid")

    # --- family heads (docker/kubectl/gh: value_flags interposition,
    # multi-token verb paths, FAMILY_EXTRAS) ---
    def test_docker(self):
        self.assert_rewrites("docker ps")
        self.assert_rewrites("docker ps -a")
        self.assert_rewrites("docker compose ps -a")
        self.assert_rewrites("docker system df -v")

    def test_kubectl(self):
        self.assert_rewrites("kubectl get pods")
        self.assert_rewrites("kubectl -n prod get pods")
        self.assert_rewrites("kubectl get pods -n prod")
        self.assert_rewrites("kubectl get pods -o json")

    def test_gh_value_flag_interposed_in_verb_path(self):
        self.assert_rewrites("gh issue --repo o/r list")
        self.assert_rewrites("gh pr -R o/r list")

    def test_bq_dry_run_required(self):
        self.assert_rewrites("bq query --dry_run \"SELECT 1\"")
        self.assert_not_rewritten('bq query "SELECT 1"')


class RewriteSpecGenericNegativeTests(unittest.TestCase):
    def assert_not_rewritten(self, command):
        self.assertIsNone(rewrite(command), command)

    def test_unknown_flag_rejected(self):
        for command in ("git status --actx-unknown-flag",
                         "docker ps --actx-unknown-flag",
                         "cargo check --actx-unknown-flag",
                         "kubectl get pods --actx-unknown-flag"):
            self.assert_not_rewritten(command)

    def test_long_flag_abbreviation_rejected(self):
        # git's --oneline has no abbreviation logic in the engine.
        self.assert_not_rewritten("git log --onelin")
        self.assert_not_rewritten("git log --one")

    def test_cluster_with_value_flag_letter_rejected(self):
        # grep's cluster admits only bool short flags; "-A" needs a value.
        self.assert_not_rewritten("grep -iA file")

    def test_optional_flag_followed_by_unknown_flag_rejected(self):
        self.assert_not_rewritten("git status --porcelain --actx-unknown-flag")

    def test_value_flag_followed_by_dash_token_not_consumed_as_value(self):
        self.assert_not_rewritten("git log --author -oneline")
        self.assert_not_rewritten("psql -d -x")


class RewriteSpecPlanPinTests(unittest.TestCase):
    """Plan `2026-09-27-gate-split-allowlist.md` STEP-W5 explicit text +
    TK-57 E-001 finding pins (rewriter-owned subset)."""

    def assert_not_rewritten(self, command):
        self.assertIsNone(rewrite(command), command)

    def test_cargo_test_forwarded_libtest_flags_rejected(self):
        self.assert_not_rewritten("cargo test -- --logfile x")

    def test_go_test_forwarded_binary_flags_rejected(self):
        self.assert_not_rewritten("go test ./... -args -test.coverprofile=x")

    def test_tk57_e001_findings_stay_fixed(self):
        for command in (
            "flyctl status --app other",
            "wrangler whoami --config other.toml",
            "uv run next dev",
            "uv run next start",
            "uv run next telemetry",
            r"find . -exec sh -x {} \;",
            r"find . -exec sh -c 'echo ok' {} \;",
            "git config --type path core.pager /tmp/x",
            "git fetch --upl=x .",
            "git push --rece=x origin",
            "git push --ex=x origin",
        ):
            self.assert_not_rewritten(command)

    def test_wave_20260927_finding_a_value_names_a_program_or_module(self):
        # Finding A (Critical, acceptance REJECT): a value flag's VALUE can
        # inline-specify a program/init-script/module to execute or load -
        # each of these was confirmed live to rewrite before the fix.
        for command in (
            "cargo test --config build.rustc-wrapper=/usr/bin/false --no-run",
            "cargo build -Z unstable-options",
            "./gradlew --init-script evil.gradle build",
            "./gradlew -I evil.gradle build",
            "ruff check --config fix=true .",
            "vitest run --environment ./evil-env.js",
            "tsc --plugins ./evil-plugin.js",
        ):
            self.assert_not_rewritten(command)

    def test_wave_20260927_finding_b_cargo_fmt_emit_files_rejected(self):
        # Finding B (Critical): rustfmt `--emit files`/`--emit=files`
        # WRITES formatted output back to the source files - only
        # `--emit stdout` is read-only. The old (pre-TK-60) rewriter
        # rejected both write spellings by name; the closed forward-spec
        # domain must reject them too, not just admit the safe value.
        for command in (
            "cargo fmt --check -- --emit files",
            "cargo fmt --check -- --emit=files",
            "cargo fmt --check -- --emit file",
        ):
            self.assert_not_rewritten(command)

    def test_wave_20260927_finding_b_cargo_fmt_emit_stdout_still_rewrites(self):
        self.assertEqual(
            rewrite("cargo fmt --check -- --emit stdout"),
            "actx cargo fmt --check -- --emit stdout",
        )


if __name__ == "__main__":
    unittest.main()
