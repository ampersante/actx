"""TK-63 regression samples: T4 literal-target zones and find classes,
closed grammars for ask -> no decision (gradlew, cargo publish, git clean,
pg_restore), git core.pager, the T1 environment reason, and the hang policy
behind global options and run-prefixes.

Every case runs under the fixture HOME (/Users/actx-fixture-user) and only
classifies: no command is executed. Exhaustive matrices live outside the
suite; this file holds a fixed sample of each.
"""

import os
import unittest

from actx_lib import hang_policy, security_gate

FIXTURE_HOME = "/Users/actx-fixture-user"


def _verdict(command):
    decision = security_gate.evaluate_security(command)
    return decision.decision, decision.category


class _FixtureHome(unittest.TestCase):
    def setUp(self):
        self._orig_home = os.environ.get("HOME")
        os.environ["HOME"] = FIXTURE_HOME

    def tearDown(self):
        if self._orig_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._orig_home

    def assertT4Deny(self, command):
        self.assertEqual(_verdict(command), ("deny", "T4_DESTRUCTIVE_MUTATION"), command)

    def assertNoT4Deny(self, command):
        self.assertNotEqual(
            security_gate.evaluate_security(command).category,
            "T4_DESTRUCTIVE_MUTATION",
            command,
        )

    def assertDeny(self, command):
        self.assertEqual(security_gate.evaluate_security(command).decision, "deny", command)


class LiteralTargetZoneTests(_FixtureHome):
    """CHK-01 / CHK-02 sample."""

    def test_spelling_matrix_is_one_verdict(self):
        expected = {
            "proj": "deny",
            "proj/build": "allow",
            ".aws/x": "deny",
            "Downloads/*": "deny",
            "Library/Keychains": "deny",
        }
        for rel, want in expected.items():
            forms = [
                "~/" + rel,
                FIXTURE_HOME + "/" + rel,
                "~//" + rel,
                "~/./" + rel,
            ]
            if not rel.endswith("*"):
                forms.append("~/" + rel + "/")
                forms.append('"$HOME/' + rel + '"')
                forms.append('"${HOME}/' + rel + '"')
            for form in forms:
                got = security_gate.evaluate_security("rm -rf " + form).decision
                self.assertEqual(got, want, form)

    def test_deep_home_and_temp_targets_have_no_t4_deny(self):
        for target in (
            "~/proj/build",
            "~/proj/build/*",
            '"$HOME/proj/build"',
            "~/Work/product-dev/actx/build",
            "~/Documents/proj/build",
            FIXTURE_HOME + "/proj/build",
            "/private/tmp/x",
            "/private/tmp/x/sub",
            "/tmp/x",
            "/tmp/x/*",
            "/var/tmp/x",
            "/var/folders/ab/cd/T/x",
            "~/Library/Developer/Xcode/DerivedData",
        ):
            self.assertNoT4Deny("rm -rf " + target)
        for command in (
            "chmod -R 755 ~/proj/x",
            "chown -R alice ~/proj/x",
            "rm -r -f ~/proj/build",
            "rm -rf -- ~/proj/build",
        ):
            self.assertNoT4Deny(command)

    def test_shallow_home_store_temp_root_and_dotdot_deny(self):
        for target in (
            "~", "~/", "$HOME", "~/*", "~/proj", "~/proj/*",
            FIXTURE_HOME + "/proj", "/Users/other/proj", "/Users/*",
            "/", "/*", "/Volumes", "/Applications", "/mnt", "/tmp", "/tmp/*",
            "/private/tmp", "/usr/lib", "~/Library/*",
            "~/proj/../..", '"$HOME"/x/..', "/Users/alice/a/../..", "/tmp/x/../y",
        ):
            self.assertT4Deny("rm -rf " + target)

    def test_one_dangerous_target_among_several_denies(self):
        self.assertT4Deny("rm -rf ~/proj/build ~/.ssh/x")
        self.assertT4Deny("rm -rf ~/proj/build /tmp")

    def test_protected_stores_deny_at_any_depth(self):
        for target in (
            "~/.gnupg/private-keys-v1.d", "~/.aws/x", "~/.kube/x", "~/.docker/x",
            "~/.config/gcloud", "~/.CONFIG/x", "~/.local/share", "~/.local/share/*",
            '"$HOME/Library/Mobile Documents/x"', '"$HOME/Library/Application Support"',
            "~/.claude/x/y", FIXTURE_HOME + "/.ssh/x", FIXTURE_HOME + "/.aws/x",
            FIXTURE_HOME + "/Library/Keychains", "/Users/other/.aws/x",
            "/home/other/.ssh/x", "/etc/ssh/x", "/System/Library/x",
        ):
            self.assertDeny("rm -rf " + target)

    def test_targets_outside_the_grammar_keep_todays_verdict(self):
        for target in (
            "~/.*", "~/*/build", "~/proj/.*", "~/.[.]", "~/x/^y", "~/x/[^a]",
            "~/Library/Keycha[^x]ns", "~/a/b/$X", "$HOME/a/b/${X}", "~/a/b/{c,d}",
            "~/.config/mc?", "~/Library/K*", "~/proj/bu\\ild",
        ):
            self.assertT4Deny("rm -rf " + target)
        for target in ("~user/x/y", "~+/x/y", "$HOMEx/a/b", "..", "../.."):
            self.assertEqual(_verdict("rm -rf " + target), ("allow", None), target)

    def test_inner_quote_word_split_is_not_a_bypass(self):
        # The fast tokenizer splits ~/Library/Keych"ains" in two; the zone
        # verdict must see the whole shell word.
        self.assertT4Deny('rm -rf ~/Library/Keych"ains"')

    def test_tainted_commands_keep_todays_verdict(self):
        for command in (
            "HOME=/x; rm -rf ~/a/b",
            "export HOME=/; rm -rf ~/a/b",
            "declare -x HOME=/ && rm -rf $HOME/a/b",
            "HOME=/ rm -rf ~/x/y",
            "unset HOME; rm -rf ~/a/b",
            "export H''OME=/; rm -rf ~/a/b",
            "export HO\\ME=/; rm -rf ~/a/b",
            "v=HO; export ${v}ME=/; rm -rf ~/a/b",
            "export HO{M,}E=/; rm -rf ~/a/b",
            "source x; rm -rf ~/a/b",
            "export HOME=\"$HOME/.config\"; sh -c 'rm -rf ~/mcp/x'",
            "sh -c 'rm -rf ~/proj/build'",
            "builtin source /tmp/e.sh; rm -rf ~/usr/lib",
            "command . ./e.sh && rm -rf ~/usr/lib",
            "{ . ./e.sh; rm -rf ~/usr/lib; }",
            "time source ./e.sh; rm -rf ~/usr/lib",
            "true;. ./e.sh; rm -rf ~/usr/lib",
            "(source ./e.sh); rm -rf ~/usr/lib",
            'export HO\\\nME="$HOME/.config"; rm -rf ~/mcp/x',
            "find . -name x; rm -rf ~/proj/build",
        ):
            self.assertT4Deny(command)


class FindClassTests(_FixtureHome):
    """CHK-03 sample."""

    def test_read_only_find_forms_have_no_t4_deny(self):
        for command in (
            "find ~/proj -exec stat {} \\;",
            "find /private/tmp/x -mtime -7 -exec grep -l foo {} +",
            "find ~/proj -name x -type f -exec /usr/bin/stat {} \\;",
            "find ~/proj -name '*.py' -exec stat {} \\;",
            "find ~/proj -perm -644 -print -exec head -n 1 {} \\;",
            "find ~/proj -exec tail -n 5 {} \\;",
            "find ~/proj/build -exec stat {} \\;",
            "find ~/.claude/projects -execdir ls {} \\;",
        ):
            self.assertNoT4Deny(command)

    def test_credential_shallow_and_system_scopes_deny(self):
        for command in (
            "find ~ -exec stat {} +",
            "find / -exec stat {} \\;",
            "find /Users -exec ls {} \\;",
            "find /home -exec stat {} \\;",
            "find /Users/other -exec ls {} \\;",
            "find ~/.aws -exec cat {} +",
            "find " + FIXTURE_HOME + "/.aws -exec cat {} \\;",
            "find " + FIXTURE_HOME + "/.aws -delete",
            "find ~/Library -exec ls {} \\;",
            "find /etc -exec cat {} +",
            "find /usr/lib -exec grep x {} +",
            "find ~/.codex -exec cat {} +",
            "find ~/.claude -exec grep x {} +",
        ):
            self.assertT4Deny(command)

    def test_non_read_only_expressions_deny(self):
        for tail in (
            "-exec rm {} \\;",
            "-exec sh -c 'x' \\;",
            "-exec xargs {} \\;",
            "-exec ./cat {} \\;",
            "-exec /usr/local/bin/cat {} \\;",
            "-exec file -C -m x {} \\;",
            "-exec tail -f {} \\;",
            "-exec tail -nf 5 {} \\;",
            "-exec tail --fol {} \\;",
            "-exec tail --follow=name {} \\;",
            "-exec tail -r {} \\;",
            "-ok stat {} \\;",
            "-fprint out -exec stat {} \\;",
            "-fls out -exec stat {} \\;",
            "-fprintf out x -exec stat {} \\;",
            "-delete -exec stat {} \\;",
            "-unknownprimary -exec stat {} \\;",
            "-exec stat {} \\; -exec rm {} \\;",
            "-delete",
        ):
            self.assertDeny("find ~/proj " + tail)
        self.assertT4Deny("find ~/proj/build -delete")
        self.assertT4Deny("find ~/proj/build -exec rm {} \\;")


class ClosedGrammarAskTests(_FixtureHome):
    """CHK-04 / CHK-05 sample."""

    def assertNoDecision(self, command):
        self.assertEqual(_verdict(command), ("allow", None), command)

    def assertAsk(self, command):
        self.assertEqual(security_gate.evaluate_security(command).decision, "ask", command)

    def test_gradlew_local_release_tasks(self):
        for task in (
            "assembleRelease", "bundleRelease", "assembleFreeRelease",
            "signingReport", "publishToMavenLocal",
            "publishMavenPublicationToMavenLocal", ":app:assembleRelease",
        ):
            self.assertNoDecision("./gradlew " + task)
        for task in (
            "assembleAndPublish", "assembleReleaseAndUpload", "assembleSignedRelease",
            "publishToMavenLocalRepository", "publishToMavenCentral", "publish",
        ):
            self.assertAsk("./gradlew " + task)

    def test_cargo_publish_dry_run(self):
        self.assertNoDecision("cargo publish --dry-run")
        self.assertNoDecision("cargo publish -n --allow-dirty")
        self.assertNoDecision("cargo publish --dry-run -p mycrate")
        for command in (
            "cargo publish",
            "cargo publish --token x -n",
            "cargo publish --registry -n",
        ):
            self.assertAsk(command)

    def test_git_clean_dry_run(self):
        for command in (
            "git clean -n -x", "git clean -ndx", "git clean -nq -X",
            "git clean --dry-run -x",
        ):
            self.assertNoDecision(command)
        for command in (
            "git clean -fdx", "git clean -fdxe -n", "git clean -fxe -n",
            "git clean -fdx -e -n", "git clean -fdx -- -n",
            "git clean -n --no-dry-run -fx", "git clean -xen", "git clean -ni -x",
            "git clean --dry -x", "git clean -n -x -- foo", "git clean -n -x foo",
        ):
            self.assertAsk(command)
        self.assertNoDecision("git clean -f")
        self.assertNoDecision("git clean -ne x")

    def test_pg_restore_list_only(self):
        self.assertNoDecision("pg_restore -l dump.bin")
        self.assertNoDecision("pg_restore --list -F c dump.bin")
        self.assertNoDecision("pg_restore -l --format=tar -v dump.tar")
        for command in (
            "pg_restore -d db dump",
            "pg_restore -l -f ~/.zshrc dump",
            "pg_restore -lf out dump",
            "pg_restore -l --file=out dump",
            "pg_restore -l -d db dump",
            "pg_restore -l a b",
            "pg_restore dump",
        ):
            self.assertAsk(command)

    def test_git_core_pager_cat_or_empty_is_no_pager(self):
        reference = _verdict("git --no-pager log")
        for command in (
            "git -c core.pager=cat log",
            "git -c core.pager= log",
            "git -c Core.Pager=cat log",
        ):
            self.assertEqual(_verdict(command), reference, command)
        for command in (
            "git -c core.pager=less log",
            "git -c core.pager='sh -c x' log",
            "git -c 'core.pager=cat ' log",
            "git --config-env core.pager=cat log",
            "git -ccore.pager=cat log",
        ):
            self.assertAsk(command)


class SingleCommandGrammarTests(_FixtureHome):
    """Every loosening needs a single simple command inside the closed
    grammar; each negative is a passing command plus one offending element
    and keeps today's verdict."""

    def test_loosened_single_commands(self):
        for command in (
            "find ~/proj -name '*.py' -exec stat {} \\;",
            "find ~/proj -exec stat {} ';'",
            'rm -rf "$HOME/proj/build"',
            "rm -rf ~/proj/build",
            "git -c core.pager=cat log",
            "git clean -n -x",
            "./gradlew assembleRelease",
            "cargo publish --dry-run",
            "pg_restore -l dump.bin",
        ):
            self.assertEqual(_verdict(command), ("allow", None), command)

    def test_space_store_through_double_quotes_denies(self):
        self.assertT4Deny('rm -rf "$HOME/Library/Application Support/x"')

    def test_each_rule_violation_keeps_todays_t4_deny(self):
        for command in (
            "rm -rf ~/proj/build && true",          # chain
            "true; rm -rf ~/proj/build",            # chain
            "rm -rf ~/proj/build\ntrue",            # newline
            "X=1 rm -rf ~/proj/build",              # assignment prefix
            "env rm -rf ~/proj/build",              # wrapper
            "rm -rf $HOME/proj/build",              # unquoted $
            'rm -rf "~/proj/build"',                # quoted ~
            "rm -rf '$HOME/proj/build'",            # single-quoted $HOME
            "rm -rf ~/proj/build>out",              # attached redirection
            "find ~/proj '(' -name a ')' -exec stat {} +",  # parentheses
            "find ~/proj ( -name a ) -exec stat {} +",      # parentheses
            "find ~/proj -name *.py -exec stat {} \\;",     # unquoted glob in a value
            "rm -rf =x ~/proj/build",               # leading =
            'rm -rf ~/proj/build ";"',              # quoted operator character
            'find ~/proj -exec stat {} ";"',        # quoted operator character
        ):
            self.assertT4Deny(command)

    def test_each_rule_violation_keeps_todays_ask(self):
        for command in (
            "git -c core.pager=cat log && true",
            'git -c core.pager=c"at" log',          # intra-word quote
            "git clean -n -x; true",
            "X=1 git clean -n -x",
            "./gradlew assembleRelease && true",
            "cargo publish --dry-run && true",
            "pg_restore -l dump.bin && true",
        ):
            self.assertEqual(security_gate.evaluate_security(command).decision, "ask", command)

    def test_temp_roots_are_class_k_for_find(self):
        for root in ("/tmp", "/private/tmp", "/var/tmp"):
            self.assertNoT4Deny("find " + root + " -exec stat {} +")


class InlineEnvironmentReasonTests(_FixtureHome):
    """CHK-06 sample: the decision is unchanged, only the reason text."""

    def test_attribute_access_names_the_environment(self):
        for command in (
            'python3 -c "import os;print(os.environ)"',
            "python3 -c \"import os;print(os.environ['X'])\"",
            "python3 -c \"import os; print(os.environ.get('HOME'))\"",
            'node -e "console.log(process.env)"',
            'node -e "console.log(process.env.X)"',
        ):
            decision = security_gate.evaluate_security(command)
            self.assertEqual(decision.decision, "deny", command)
            self.assertIn("process environment", decision.reason, command)
            self.assertNotIn(".env'", decision.reason, command)

    def test_path_literals_keep_the_path_reason(self):
        for command in (
            "python3 -c \"open('.env').read()\"",
            "python3 -c \"open('app.env').read()\"",
        ):
            decision = security_gate.evaluate_security(command)
            self.assertEqual(decision.decision, "deny", command)
            self.assertIn("sensitive path '.env'", decision.reason, command)


class HangPolicyGlobalOptionTests(unittest.TestCase):
    """CHK-08 sample."""

    def test_follow_and_watch_behind_global_options_never_wrap(self):
        for command in (
            "docker -H x logs -f c",
            "docker --context x logs -f c",
            "docker -H=x logs --follow c",
            "docker -D logs -f c",
            "docker --tls logs -f c",
            "kubectl -n x get pods -w",
            "kubectl --namespace x --watch get pods",
            "kubectl --request-timeout 5s get pods -w",
            "kubectl -s https://x get pods --watch",
            "uv run docker logs -f c",
        ):
            self.assertEqual(hang_policy.classify(command.split()), "never_wrap", command)

    def test_file_flags_and_plain_verbs_unchanged(self):
        for command in (
            "docker build -f Dockerfile .",
            "kubectl apply -f x",
            "docker -H x ps",
            "kubectl -n x get pods",
        ):
            self.assertNotEqual(hang_policy.classify(command.split()), "never_wrap", command)

    def test_run_prefix_returns_the_inner_class(self):
        for argv in (["pytest"], ["tail", "-f", "x"], ["docker", "compose", "up", "-d"], ["ls"]):
            self.assertEqual(
                hang_policy.classify(["uv", "run"] + argv), hang_policy.classify(argv), argv
            )


if __name__ == "__main__":
    unittest.main()
