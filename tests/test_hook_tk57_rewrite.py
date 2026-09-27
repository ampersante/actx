"""TK-57 stream B hook probes (plan v4 S7): every rewriter-owned STEP
(STEP-02 sqlite3/duckdb, STEP-03 endpoint/credential/project flags,
STEP-04 `next`, STEP-04b `find` write actions, STEP-06 rewriter part git
exec-flags) exercised through the real hook entrypoint on BOTH schemas
(Claude/Codex and Antigravity), so a regression in hook.py's own
plumbing - not just rewriter.py/sql_verbs.py in isolation - is caught.

Kept as its own file (not tests/test_hook.py) so stream A (security_gate.py
+ test_hook.py) and stream B (rewriter.py/sql_verbs.py) never touch the
same test file in parallel worktrees (plan v4 S7)."""

import json
import os
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


def hook_input(tool_name, tool_input):
    return json.dumps({"tool_name": tool_name, "tool_input": tool_input})


def gemini_input(tool_name, args):
    return json.dumps({"toolCall": {"name": tool_name, "args": args}})


class HookRewriteProbeTests(unittest.TestCase):
    def run_hook(self, stdin_text):
        return subprocess.run(
            [ACTX, "hook"],
            input=stdin_text,
            capture_output=True,
            text=True,
        )

    def assert_allow_rewritten(self, command):
        """Both schemas auto-approve AND rewrite `command` to `actx
        <command>` verbatim."""
        expected = "actx " + command

        p = self.run_hook(hook_input("Bash", {"command": command}))
        self.assertEqual(p.returncode, 0, (command, p.stderr))
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "allow", command)
        self.assertEqual(
            output["updatedInput"]["command"], expected, command
        )

        p = self.run_hook(gemini_input("run_command", {"CommandLine": command}))
        self.assertEqual(p.returncode, 0, (command, p.stderr))
        data = json.loads(p.stdout)
        self.assertEqual(data["decision"], "allow", command)
        self.assertEqual(
            data["overwrite"]["CommandLine"], expected, command
        )

    def assert_not_auto_allowed(self, command):
        """Neither schema auto-approves `command` - Claude/Codex either
        defers (empty stdout) or asks; Antigravity never returns
        "allow" (ask/force_ask/deny are all acceptable non-allow
        outcomes)."""
        p = self.run_hook(hook_input("Bash", {"command": command}))
        self.assertEqual(p.returncode, 0, (command, p.stderr))
        if p.stdout.strip():
            data = json.loads(p.stdout)
            decision = data["hookSpecificOutput"]["permissionDecision"]
            self.assertNotEqual(decision, "allow", command)

        p = self.run_hook(gemini_input("run_command", {"CommandLine": command}))
        self.assertEqual(p.returncode, 0, (command, p.stderr))
        data = json.loads(p.stdout)
        self.assertNotEqual(data["decision"], "allow", command)

    # -- STEP-02: sqlite3/duckdb mode flags + all-positionals SQL -------

    def test_step02_ro_forms_allow(self):
        for command in (
            "sqlite3 db 'SELECT 1'",
            "sqlite3 -json db 'select 1'",
            "sqlite3 -readonly db 'SELECT 1'",
            "sqlite3 -separator , db 'select 1'",
            "sqlite3 -cmd 'select 1' db 'select 2'",
            "psql -c 'SELECT 1'",
        ):
            with self.subTest(command=command):
                self.assert_allow_rewritten(command)

    def test_step02_mode_flags_and_dangerous_payloads_not_allowed(self):
        for command in (
            'sqlite3 -cmd "PRAGMA user_version=123" db "SELECT 1"',
            "sqlite3 --cmd '.load ./x' db 'select 1'",
            "sqlite3 db 'DROP TABLE t' 'SELECT 1'",
            "sqlite3 db 'DROP TABLE t' -separator 'SELECT 1'",
            "sqlite3 -A -x a.sar SELECT",
            "sqlite3 --A -x a.sar SELECT",
            "sqlite3 -Ax a.sar SELECT",
            "sqlite3 -append db 'select 1'",
            "sqlite3 -zip a.zip 'select 1'",
            "sqlite3 -unsafe-testing db 'select 1'",
            "sqlite3 --init boot.sql db 'select 1'",
            "sqlite3 -init boot.sql db 'select 1'",
            "duckdb -unsigned db 'select 1'",
        ):
            with self.subTest(command=command):
                self.assert_not_auto_allowed(command)

    # -- STEP-03: endpoint/credential/project flag class ----------------

    def test_step03_ro_forms_allow(self):
        for command in (
            "docker ps -a",
            "docker system df -v",
            "kubectl get pods -n prod --context x",
            "kubectl get pods -o wide",
            "kubectl get pods -ojson",
            "kubectl get pods -A",
            "helm list",
            "bq ls",
            "gh pr list",
            "gh pr -R o/r list",
            "gh issue --repo o/r list",
            "gh --repo=o/r pr list",
        ):
            with self.subTest(command=command):
                self.assert_allow_rewritten(command)

    def test_step03_endpoint_flags_not_allowed(self):
        for command in (
            "docker ps -H tcp://e:2375",
            "docker -H tcp://e ps",
            "docker ps --host=tcp://e",
            "kubectl get pods --as=admin",
            "kubectl get pods -As https://evil:6443",
            "kubectl get pods -s=https://e",
            "kubectl get pods --server https://e",
            "kubectl get pods --user=admin",
            "helm list --kube-token x",
            "helm list --kube-context prod",
            "gcloud projects list --impersonate-service-account=a@b",
            "gcloud projects list --project p",
            "gcloud projects list --flags-file f.yaml",
            "bq ls --project_id=p",
            "bq ls -credential_file=x",
            "vercel whoami --token x",
            "vercel list --scope t",
            "flyctl status --access-token x",
            "gh pr list --hostname e.com",
        ):
            with self.subTest(command=command):
                self.assert_not_auto_allowed(command)

    # -- STEP-04: `next` closed RO-subcommand list -----------------------

    def test_step04_ro_subcommands_allow(self):
        for command in ("next lint", "next build", "next info"):
            with self.subTest(command=command):
                self.assert_allow_rewritten(command)

    def test_step04_other_forms_not_allowed(self):
        for command in (
            "next",
            "next dev",
            "next start -p 3000",
            "next telemetry disable",
            "next lint --fix",
        ):
            with self.subTest(command=command):
                self.assert_not_auto_allowed(command)

    # -- STEP-04b: `find` write actions (-fprint0 sibling) ---------------

    def test_step04b_find_write_action_not_allowed(self):
        self.assert_not_auto_allowed("find . -fprint0 /tmp/out")

    def test_step04b_plain_find_allows(self):
        self.assert_allow_rewritten("find . -name '*.py'")

    # -- STEP-06 rewriter part: git argv exec-flags ----------------------

    def test_step06_exec_flags_not_allowed(self):
        for command in (
            "git fetch --upload-pack='touch x' .",
            "git pull --upload-pack=x",
            "git push --receive-pack=x origin",
            "git push --exec=x origin",
        ):
            with self.subTest(command=command):
                self.assert_not_auto_allowed(command)

    def test_step06_ro_and_unrelated_forms_allow(self):
        for command in (
            "git fetch",
            "git pull --rebase",
            "git push origin main",
            "git push --recurse-submodules=check",
        ):
            with self.subTest(command=command):
                self.assert_allow_rewritten(command)


class InlineCodeBoundaryTests(unittest.TestCase):
    """Owner boundary 2026-09-27 (PRD §7): code written INLINE in argv is
    never auto-approved; selecting a file/directory/project is equivalent
    to `cd` there and running the same verb, so it stays rewritten."""

    run_hook = HookRewriteProbeTests.run_hook
    assert_allow_rewritten = HookRewriteProbeTests.assert_allow_rewritten
    assert_not_auto_allowed = HookRewriteProbeTests.assert_not_auto_allowed

    def test_inline_code_not_auto_allowed(self):
        for command in (
            "cargo test --config 'build.rustc-wrapper=\"/usr/bin/false\"' --no-run",
            "cargo check -Zunstable-options",
            "ruff check --config 'fix = true' .",
            "cargo fmt --check -- --emit files",
        ):
            with self.subTest(command=command):
                self.assert_not_auto_allowed(command)

    def test_file_and_project_selectors_rewrite(self):
        for command in (
            "./gradlew --init-script init.gradle tasks",
            "./gradlew -b other.gradle tasks",
            "./gradlew -Dorg.gradle.jvmargs=-Xmx2g test",
            "./gradlew -Pkotlin.incremental=true build",
            "jest --config jest.config.js",
            "eslint --config eslint.config.js .",
            "kubectl --kubeconfig /tmp/cfg get pods",
            "cargo check --manifest-path sub/Cargo.toml",
            "git add --auto-advance -A",
        ):
            with self.subTest(command=command):
                self.assert_allow_rewritten(command)


class FindExecInterpreterFormsTests(unittest.TestCase):
    def verdict(self, command):
        from actx_lib import security_gate
        return security_gate.evaluate_security(command)

    def test_known_script_forms_not_escalated(self):
        for command in (
            "find . -exec sh -- known.sh {} \\;",
            "find . -exec python3 -- known.py {} \\;",
            "find . -exec bash -ex known.sh {} \\;",
            "find . -exec python3 -bb known.py {} \\;",
            "find . -exec node --no-warnings known.js {} \\;",
            "find . -exec node --max-old-space-size=4096 known.js {} \\;",
            "find . -exec bash --norc known.sh {} \\;",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command).decision, "allow")

    def test_placeholder_as_script_asks(self):
        for command in (
            "find . -exec sh -- {} \\;",
            "find . -exec bash -ex {} \\;",
            "find . -exec bash -xc 'echo' {} \\;",
            "find . -exec bash --rcfile rc {} \\;",
            "find . -exec python3 --check-hash-based-pycs always {} \\;",
            "find . -exec node --require={} x.js \\;",
        ):
            with self.subTest(command=command):
                dec = self.verdict(command)
                self.assertEqual((dec.decision, dec.category),
                                 ("ask", "T4_DESTRUCTIVE_MUTATION"))


if __name__ == "__main__":
    unittest.main()
