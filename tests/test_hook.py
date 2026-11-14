import io
import json
import os
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


def hook_input(tool_name, tool_input):
    return json.dumps({"tool_name": tool_name, "tool_input": tool_input})


def gemini_input(tool_name, args):
    return json.dumps({"toolCall": {"name": tool_name, "args": args}})


class HookCliTests(unittest.TestCase):
    def run_hook(self, stdin_text):
        return subprocess.run(
            [ACTX, "hook"],
            input=stdin_text,
            capture_output=True,
            text=True,
        )

    # ------------------------------------------------------------------
    # Antigravity CLI (Gemini) Hook Schema Tests
    # ------------------------------------------------------------------
    def test_gemini_run_command_rewritten(self):
        payload = gemini_input("run_command", {"CommandLine": "git status"})
        p = self.run_hook(payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data, {
            "decision": "allow",
            "overwrite": {"CommandLine": "actx git status"},
        })

    def test_gemini_run_command_safe_uncompressed_ask(self):
        # TK-55 F1: a safe uncompressed command no longer gets an explicit
        # "allow" - the Antigravity fallthrough defers via "ask".
        payload = gemini_input("run_command", {"CommandLine": "python3 -c \"import sys; print(sys.version)\""})
        p = self.run_hook(payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["decision"], "ask")
        self.assertIsInstance(data["reason"], str)
        self.assertTrue(data["reason"])

    def test_gemini_run_command_unknown_command_asks(self):
        # TK-55 F1 regression pin ("the touch hole"): a command outside
        # the gate lists and the rewriter allow-list must not be
        # auto-approved on the Antigravity schema.
        payload = gemini_input("run_command", {"CommandLine": "touch /tmp/x"})
        p = self.run_hook(payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["decision"], "ask")
        self.assertIsInstance(data["reason"], str)

    def test_gemini_run_command_denied(self):
        payload = gemini_input("run_command", {"CommandLine": "cat .env"})
        p = self.run_hook(payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["decision"], "deny")
        self.assertIn("Access to sensitive credential/file '.env' is prohibited", data["reason"])

    def test_gemini_run_command_ask(self):
        payload = gemini_input("run_command", {"CommandLine": "git push --force origin main"})
        p = self.run_hook(payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["decision"], "force_ask")
        self.assertEqual(data["reason"], (
            "actx security gate confirmation required [T6_HIGH_RISK_GIT] "
            "'git push --force origin main': rewrites remote git history or "
            "refs and can affect what everyone else sees — "
            "Force-pushing to remote git repository requires human confirmation"
        ))

    def test_gemini_secret_class_bare_operand_denied(self):
        # TK-57 S1 (STEP-01): matches the Claude-schema pin above.
        payload = gemini_input("run_command", {"CommandLine": "cat client_secret"})
        p = self.run_hook(payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["decision"], "deny")
        self.assertIn("client_secret", data["reason"])

    def test_gemini_git_config_alias_exec_class_asks(self):
        # TK-57 S7 (STEP-06 gate part): matches the Claude-schema pin above.
        payload = gemini_input("run_command", {"CommandLine": "git config alias.p '!id'"})
        p = self.run_hook(payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["decision"], "force_ask")
        self.assertEqual(data["reason"], (
            "actx security gate confirmation required [T6_HIGH_RISK_GIT] "
            "'git config alias.p '\"'\"'!id'\"'\"'': rewrites remote git "
            "history or refs and can affect what everyone else sees — "
            "Setting git config key 'alias.p' can redirect git into "
            "executing an arbitrary program"
        ))

    def test_gemini_find_exec_escaped_semicolon_denied(self):
        # TK-57 S6 (STEP-05): matches the Claude-schema pin above.
        payload = gemini_input("run_command", {"CommandLine": "find . -type f -exec sudo rm -rf {} \\;"})
        p = self.run_hook(payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["decision"], "deny")
        self.assertIn("Privilege escalation", data["reason"])

    def test_gemini_action_space_denied(self):
        payload = gemini_input("run_command", {"CommandLine": "sed -i 's/foo/bar/g' main.py"})
        p = self.run_hook(payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["decision"], "deny")
        self.assertIn("In-place stream editing via shell is prohibited", data["reason"])

    def test_gemini_unsupported_tool_call_empty(self):
        payload = gemini_input("view_file", {"AbsolutePath": "/path/to/file"})
        p = self.run_hook(payload)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_gemini_missing_command_line_empty(self):
        payload = gemini_input("run_command", {})
        p = self.run_hook(payload)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    # ------------------------------------------------------------------
    # Claude Code / Codex CLI Hook Schema Tests
    # ------------------------------------------------------------------
    def test_codex_exec_tool_rewritten(self):
        p = self.run_hook(hook_input("exec", {"command": "git diff"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(
            data["hookSpecificOutput"]["updatedInput"]["command"],
            "actx git diff",
        )

    def test_git_status_rewritten_with_all_keys(self):
        payload = hook_input(
            "Bash",
            {"command": "git status", "description": "status", "timeout": 5000},
        )
        p = self.run_hook(payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stderr, "")
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertEqual(output["additionalContext"], "Command rewritten by actx for output compression.")
        self.assertEqual(
            output["updatedInput"],
            {"command": "actx git status", "description": "status", "timeout": 5000},
        )

    def test_snake_case_bash_rewritten(self):
        p = self.run_hook(hook_input("bash", {"command": "git diff"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(
            data["hookSpecificOutput"]["updatedInput"]["command"],
            "actx git diff",
        )

    def test_shell_tool_rewritten(self):
        p = self.run_hook(hook_input("Shell", {"command": "ls"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(
            data["hookSpecificOutput"]["updatedInput"]["command"],
            "actx ls",
        )

    def test_ls_la_rewritten(self):
        p = self.run_hook(hook_input("Bash", {"command": "ls -la"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(
            data["hookSpecificOutput"]["updatedInput"]["command"],
            "actx ls -la",
        )
        self.assertEqual(
            data["hookSpecificOutput"]["permissionDecision"], "allow"
        )

    def test_git_show_rewritten(self):
        p = self.run_hook(hook_input("Bash", {"command": "git show HEAD"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(
            data["hookSpecificOutput"]["updatedInput"]["command"],
            "actx git show HEAD",
        )

    def test_pytest_rewritten(self):
        p = self.run_hook(hook_input("Bash", {"command": "pytest -q"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(
            data["hookSpecificOutput"]["updatedInput"]["command"],
            "actx pytest -q",
        )

    def test_security_gate_denies_sensitive_file_read(self):
        p = self.run_hook(hook_input("Bash", {"command": "cat ~/.ssh/id_rsa"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("T1_CREDENTIAL_ACCESS", output["permissionDecisionReason"])

    def test_security_gate_denies_secret_class_basename(self):
        # TK-57 S1 (STEP-01, REQ-01): new secret-name basename record.
        p = self.run_hook(hook_input("Bash", {"command": "cat kubeconfig"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("T1_CREDENTIAL_ACCESS", output["permissionDecisionReason"])

    def test_security_gate_denies_secret_keyword_bare_operand(self):
        # REQ-01 condition (b): bare (no extension/'/') non-flag operand of
        # a file-read head is in scope for the 'secret' keyword class.
        p = self.run_hook(hook_input("Bash", {"command": "cat client_secret"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("T1_CREDENTIAL_ACCESS", output["permissionDecisionReason"])

    def test_security_gate_denies_git_show_secret_class(self):
        # REQ-01 git-read verbs: `git show HEAD:<path>` operand form.
        p = self.run_hook(hook_input("Bash", {"command": "git show HEAD:client_secret"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("T1_CREDENTIAL_ACCESS", output["permissionDecisionReason"])

    def test_security_gate_secret_class_negative_neighbor_unaffected(self):
        # A bare subcommand word ('secrets') on a non-file-read head stays
        # out of scope - kubectl get secrets keeps rewriting as before.
        p = self.run_hook(hook_input("Bash", {"command": "kubectl get secrets"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertEqual(output["updatedInput"]["command"], "actx kubectl get secrets")

    def test_security_gate_asks_git_config_alias_exec_class(self):
        # TK-57 S7 (STEP-06 gate part, REQ-07): alias.* (any value) asks.
        p = self.run_hook(hook_input("Bash", {"command": "git config alias.p '!id'"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "ask")
        self.assertIn("confirmation required", output["permissionDecisionReason"])

    def test_security_gate_asks_git_fetch_upload_pack(self):
        # REQ-08 (gate side).
        p = self.run_hook(hook_input("Bash", {"command": "git fetch --upload-pack='touch x' ."}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "ask")
        self.assertIn("confirmation required", output["permissionDecisionReason"])

    def test_security_gate_denies_destructive_mutation(self):
        p = self.run_hook(hook_input("Bash", {"command": "rm -rf /"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("T4_DESTRUCTIVE_MUTATION", output["permissionDecisionReason"])

    def test_security_gate_asks_on_force_push(self):
        p = self.run_hook(hook_input("Bash", {"command": "git push --force origin master"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "ask")
        self.assertIn("confirmation required", output["permissionDecisionReason"])

    def test_security_gate_denies_find_exec_escaped_semicolon(self):
        # TK-57 S6 (STEP-05): a literal '\;' must not split the find
        # command into a bogus '-exec ...' chunk (E-012) - the whole
        # invocation stays one chunk and each -exec subcommand is
        # re-checked on its own.
        p = self.run_hook(hook_input("Bash", {"command": "find . -type f -exec sudo rm -rf {} \\;"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("T4_DESTRUCTIVE_MUTATION", output["permissionDecisionReason"])

    def test_security_gate_asks_find_exec_brace_head_position(self):
        # '{}' as the executed program itself (no fixed head to classify) asks.
        p = self.run_hook(hook_input("Bash", {"command": "find /tmp -name '*.sh' -exec {} \\;"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "ask")
        self.assertEqual(output["permissionDecisionReason"], (
            "actx security gate confirmation required [T4_DESTRUCTIVE_MUTATION] "
            "'find /tmp -name '\"'\"'*.sh'\"'\"' -exec {} \\;': deletes or "
            "overwrites files and local state and cannot be undone — find "
            "executes an unknown discovered file directly ('{}' as the "
            "executed program)"
        ))

    def test_t6_infra_ask_passthrough(self):
        # TK-37: kubectl apply is a T6 ask (not denied, not rewritten)
        p = self.run_hook(hook_input("Bash", {"command": "kubectl apply -f f"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], "ask")
        self.assertIn("confirmation required", output["permissionDecisionReason"])

    def test_t6_bare_swiftformat_ask_passthrough(self):
        # TK-42 N-F11: bare swiftformat rewrites Swift files in place - the
        # dedicated gate check escalates through the hook (not rewritten).
        p = self.run_hook(hook_input("Bash", {"command": "swiftformat ."}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "ask")
        self.assertIn("confirmation required", output["permissionDecisionReason"])
        self.assertNotIn("updatedInput", output)

    def test_t5_supply_chain_install_asks(self):
        # TK-51: agent-driven installs ask (JSON permissionDecision "ask").
        for cmd in ("npm exec -y pkg", "npm init pkg", "npm install x"):
            with self.subTest(cmd=cmd):
                p = self.run_hook(hook_input("Bash", {"command": cmd}))
                self.assertEqual(p.returncode, 0, p.stderr)
                data = json.loads(p.stdout)
                output = data["hookSpecificOutput"]
                self.assertEqual(output["permissionDecision"], "ask")
                self.assertIn("confirmation required", output["permissionDecisionReason"])

    def test_t5_actx_prefixed_install_asks(self):
        # actx-prefix is unwrapped before gate checks (TK-39/TK-51).
        p = self.run_hook(hook_input("Bash", {"command": "actx run npm install x"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "ask")
        self.assertIn("confirmation required", output["permissionDecisionReason"])
        self.assertNotIn("updatedInput", output)

    def test_mutating_compound_empty(self):
        p = self.run_hook(hook_input("Bash", {"command": "git status && echo done"}))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_invalid_json_empty(self):
        p = self.run_hook("{not json")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_json_array_empty(self):
        p = self.run_hook("[]")
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_missing_tool_name_empty(self):
        p = self.run_hook(json.dumps({"tool_input": {"command": "git status"}}))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_unsupported_tool_name_empty(self):
        p = self.run_hook(hook_input("Read", {"command": "git status"}))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_tool_input_not_dict_empty(self):
        p = self.run_hook(json.dumps({"tool_name": "Bash", "tool_input": "git status"}))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_command_missing_empty(self):
        p = self.run_hook(hook_input("Bash", {"description": "no command"}))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_command_not_string_empty(self):
        p = self.run_hook(hook_input("Bash", {"command": ["git", "status"]}))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_unknown_safe_command_empty(self):
        p = self.run_hook(hook_input("Bash", {"command": "custom_script_safe.sh --foo"}))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_unknown_command_touch_defers_empty(self):
        # TK-55 F1 asymmetry pin: the same `touch` vector that yields
        # "ask" on the Antigravity schema stays a native defer (empty
        # stdout) on the claude schema.
        p = self.run_hook(hook_input("Bash", {"command": "touch /tmp/x"}))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_actx_prefix_idempotent_empty(self):
        p = self.run_hook(hook_input("Bash", {"command": "actx git status"}))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_git_log_hint_appended_to_additional_context(self):
        # TK-45 (REQ-03): allow+rewrite verdict on a verbose-form command
        # appends the conventions hint; the full text is asserted exactly.
        p = self.run_hook(hook_input("Bash", {"command": "git log"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertEqual(
            output["updatedInput"]["command"],
            "actx git log",
        )
        self.assertEqual(
            output["additionalContext"],
            "Command rewritten by actx for output compression."
            "\nadd -n N (e.g. git log -n 50 --oneline)",
        )

    def test_compact_flag_present_no_hint(self):
        # `git log -n 50` already follows the convention - no hint suffix.
        p = self.run_hook(hook_input("Bash", {"command": "git log -n 50 --oneline"}))
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(
            data["hookSpecificOutput"]["additionalContext"],
            "Command rewritten by actx for output compression.",
        )

    def test_hint_only_on_allow_rewrite_verdict(self):
        # deny: no hint suffix in the decision reason; ask: same. The
        # hint lives ONLY in the additionalContext of the rewrite path.
        p = self.run_hook(hook_input("Bash", {"command": "cat .env"}))
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertNotIn("additionalContext", output)
        self.assertNotIn("hint", json.dumps(data))

        p = self.run_hook(hook_input("Bash", {"command": "git push --force origin main"}))
        data = json.loads(p.stdout)
        output = data["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "ask")
        self.assertNotIn("additionalContext", output)

    def test_gemini_schema_never_gets_hint(self):
        # Antigravity contract has no additionalContext field at all - the
        # rewritten overwrite stays byte-identical for hint-eligible heads.
        payload = gemini_input("run_command", {"CommandLine": "git log"})
        p = self.run_hook(payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data, {
            "decision": "allow",
            "overwrite": {"CommandLine": "actx git log"},
        })

    def test_clean_command_without_rewrite_strict_none(self):
        # INV-03: a safe uncompressed command still defers strictly (empty
        # stdout) - `dart compile` is no rewriter verb and no gate target.
        p = self.run_hook(hook_input("Bash", {"command": "dart compile js"}))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

    def test_stdout_is_exact_object_no_extra_keys(self):
        p = self.run_hook(hook_input("Bash", {"command": "git status"}))
        data = json.loads(p.stdout)
        self.assertEqual(list(data), ["hookSpecificOutput"])
        output = data["hookSpecificOutput"]
        self.assertEqual(
            list(output),
            ["hookEventName", "permissionDecision", "updatedInput", "additionalContext"],
        )


# TK-65 (plan D5 §1): per-agent policy selected by `actx hook --agent <name>`.
# The mutator-policy rows below use `git commit` - a mutator outside the
# TK-70 push policy (rewrite-eligible, no protected-branch decision); push
# rows live in Tk70PushPolicyTests further down.
MUTATOR = 'git commit -m "probe commit"'
FALLBACK_MUTATOR = "git commit -m x"
PUSH = "git push origin main"
FORCE_PUSH = "git push --force origin main"
FORCE_PUSH_REASON = "Force-pushing to remote git repository requires human confirmation"
GIT_EXPLANATION = ("rewrites remote git history or refs and can affect what "
                   "everyone else sees")
# Byte-exact `actx hook` output for MUTATOR on the default (no-agent) policy.
MUTATOR_NO_AGENT_STDOUT = (
    '{"hookSpecificOutput": {"hookEventName": "PreToolUse", '
    '"permissionDecision": "allow", "updatedInput": {"command": '
    '"actx git commit -m \\"probe commit\\""}, "additionalContext": '
    '"Command rewritten by actx for output compression."}}\n'
)
FALLBACK_MUTATOR_NO_AGENT_STDOUT = (
    '{"hookSpecificOutput": {"hookEventName": "PreToolUse", '
    '"permissionDecision": "allow", "updatedInput": {"command": '
    '"actx git commit -m x"}, "additionalContext": '
    '"Command rewritten by actx for output compression."}}\n'
)
DEVIN_MUTATOR_ALLOW = {
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
    }
}


def gate_ask_as_deny(agent, category, reason):
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"actx security gate ({agent}: no confirmation channel) "
                f"[{category}]: {reason}"
            ),
        }
    }


class HookAgentPolicyTests(unittest.TestCase):
    def run_hook(self, args, command=None, stdin_text=None):
        if stdin_text is None:
            stdin_text = hook_input("Bash", {"command": command})
        return subprocess.run(
            [ACTX, "hook"] + args,
            input=stdin_text,
            capture_output=True,
            text=True,
        )

    def hook_stdout(self, args, command):
        p = self.run_hook(args, command)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    # --- mutators (git commit: outside the TK-70 push policy) -----------
    def test_opencode_mutator_not_rewritten_empty(self):
        self.assertEqual(self.hook_stdout(["--agent", "opencode"], MUTATOR), "")

    def test_devin_mutator_allow_without_updated_input(self):
        out = self.hook_stdout(["--agent", "devin"], MUTATOR)
        self.assertEqual(out, json.dumps(DEVIN_MUTATOR_ALLOW) + "\n")

    def test_pi_mutator_rewritten(self):
        self.assertEqual(self.hook_stdout(["--agent", "pi"], MUTATOR),
                         MUTATOR_NO_AGENT_STDOUT)

    def test_no_agent_mutator_rewritten_byte_identical(self):
        self.assertEqual(self.hook_stdout([], MUTATOR), MUTATOR_NO_AGENT_STDOUT)

    # --- gate verdicts --------------------------------------------------
    def test_devin_force_push_gate_ask_first(self):
        out = self.hook_stdout(["--agent", "devin"], FORCE_PUSH)
        self.assertEqual(out, self.hook_stdout([], FORCE_PUSH))
        self.assertEqual(
            json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_opencode_force_push_ask_becomes_deny(self):
        out = self.hook_stdout(["--agent", "opencode"], FORCE_PUSH)
        self.assertEqual(json.loads(out), gate_ask_as_deny(
            "opencode", "T6_HIGH_RISK_GIT", FORCE_PUSH_REASON))

    def test_pi_force_push_ask_becomes_deny(self):
        out = self.hook_stdout(["--agent", "pi"], FORCE_PUSH)
        self.assertEqual(json.loads(out), gate_ask_as_deny(
            "pi", "T6_HIGH_RISK_GIT", FORCE_PUSH_REASON))

    def test_gate_deny_unchanged_for_every_agent(self):
        # TK-64 row (replaces `actx rewrite "cat .env"` -> empty): the gate
        # deny is emitted before any rewrite, identical for every agent.
        expected = self.hook_stdout([], "cat .env")
        data = json.loads(expected)["hookSpecificOutput"]
        self.assertEqual(data["permissionDecision"], "deny")
        self.assertEqual(
            data["permissionDecisionReason"],
            "actx security gate violation [T1_CREDENTIAL_ACCESS]: "
            "Access to sensitive credential/file '.env' is prohibited",
        )
        for agent in ("opencode", "devin", "pi"):
            with self.subTest(agent=agent):
                self.assertEqual(
                    self.hook_stdout(["--agent", agent], "cat .env"), expected)

    # --- other rewrites -------------------------------------------------
    def test_observational_rewrite_unchanged_for_every_agent(self):
        expected = self.hook_stdout([], "git status")
        self.assertEqual(
            json.loads(expected)["hookSpecificOutput"]["updatedInput"],
            {"command": "actx git status"},
        )
        for agent in ("opencode", "devin", "pi"):
            with self.subTest(agent=agent):
                self.assertEqual(
                    self.hook_stdout(["--agent", agent], "git status"), expected)

    # --- malformed argv -> no-agent behaviour ---------------------------
    def test_malformed_agent_argv_falls_back_to_no_agent(self):
        # FALLBACK_MUTATOR is rewrite-eligible under the default policy, so
        # the fallback is observable as the full allow+updatedInput output.
        for args in (["--agent", "nosuch"], ["--agent"], ["--bogus"],
                     ["--agent", "opencode", "--bogus"],
                     ["--bogus", "--agent", "opencode"]):
            with self.subTest(args=args):
                p = self.run_hook(args, FALLBACK_MUTATOR)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, FALLBACK_MUTATOR_NO_AGENT_STDOUT)

    # --- --payload (A1 fallback) ----------------------------------------
    def test_payload_either_order_matches_stdin_form(self):
        # stdin carries a different command: the payload must replace it.
        # MUTATOR replaces PUSH here: the push policy (TK-70 REQ-01) has its
        # own class below; this test pins argv-order plumbing.
        decoy = hook_input("Bash", {"command": "git log"})
        for command in (MUTATOR, FORCE_PUSH, "git status"):
            expected = self.hook_stdout(["--agent", "opencode"], command)
            payload = hook_input("Bash", {"command": command})
            for args in (["--agent", "opencode", "--payload", payload],
                         ["--payload", payload, "--agent", "opencode"]):
                with self.subTest(command=command, order=args[0]):
                    p = self.run_hook(args, stdin_text=decoy)
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertEqual(p.stdout, expected)
        self.assertEqual(self.hook_stdout(["--agent", "opencode"], MUTATOR), "")
        self.assertEqual(
            json.loads(self.hook_stdout(["--agent", "opencode"], FORCE_PUSH))
            ["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(
            json.loads(self.hook_stdout(["--agent", "opencode"], "git status"))
            ["hookSpecificOutput"]["updatedInput"],
            {"command": "actx git status"})

    def test_payload_missing_or_non_json_empty(self):
        stdin_text = hook_input("Bash", {"command": "git status"})
        for args in (["--agent", "opencode", "--payload"],
                     ["--payload"],
                     ["--agent", "opencode", "--payload", "not json"],
                     ["--payload", "{", "--agent", "opencode"]):
            with self.subTest(args=args):
                p = self.run_hook(args, stdin_text=stdin_text)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, "")

    # --- gate exception -> no opinion on benign commands, every agent ---
    def test_gate_exception_empty_for_every_agent_on_benign_command(self):
        # Pins the unchanged fail-open half of TK-70 REQ-04: a gate failure
        # on a benign (non-irreversible) command still defers to the
        # harness (empty output) on every agent. The irreversible half
        # (ask / opencode+pi deny) is pinned in Tk70GateErrorAskTests.
        from actx_lib import hook

        for args in ([], ["--agent", "opencode"], ["--agent", "devin"],
                     ["--agent", "pi"]):
            with self.subTest(args=args):
                out = io.StringIO()
                with mock.patch(
                    "actx_lib.security_gate.evaluate_security",
                    side_effect=RuntimeError("boom"),
                ), mock.patch(
                    "sys.stdin", io.StringIO(hook_input("Bash", {"command": "ls -la"}))
                ), mock.patch("sys.stdout", out):
                    rc = hook.main(args)
                self.assertEqual(rc, 0)
                self.assertEqual(out.getvalue(), "")


class CodexPayloadPolicyTests(unittest.TestCase):
    run_hook = HookAgentPolicyTests.run_hook
    hook_stdout = HookAgentPolicyTests.hook_stdout

    # Synthetic Codex marker: no captured user payload or command history.
    def codex_payload(self, command, tool_name="Bash", **input_keys):
        return json.dumps({
            "turn_id": "synthetic-turn",
            "tool_name": tool_name,
            "tool_input": {"command": command, **input_keys},
        })

    def test_codex_all_git_mutators_defer_without_allow_or_rewrite(self):
        # An ordinary push to an unprotected dst defers like every other
        # git mutator under the codex policy (TK-70 REQ-01); a protected
        # dst is a gate ask, pinned in Tk70PushPolicyTests.
        for command in ("git add probe.txt", "git commit -m probe",
                        "git push origin feature", "git pull origin main",
                        "git fetch origin"):
            for tool_name in ("Bash", "exec"):
                with self.subTest(command=command, tool_name=tool_name):
                    p = self.run_hook([], stdin_text=self.codex_payload(
                        command, tool_name, description="probe", timeout=5000,
                        workdir="/synthetic/work", sandbox_permissions="require_escalated",
                        prefix_rule=["git", command.split()[1]],
                    ))
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertEqual(p.stdout, "")
                    self.assertEqual(p.stderr, "")

    def test_codex_reads_keep_complete_updated_input(self):
        for command in ("git status", "git diff", "git log -n 5 --oneline",
                        "git show HEAD", "ls -la"):
            with self.subTest(command=command):
                payload = self.codex_payload(
                    command, "exec", description="read", timeout=5000,
                    workdir="/synthetic/work", prefix_rule=["git"],
                )
                p = self.run_hook([], stdin_text=payload)
                expected = json.loads(payload)
                del expected["turn_id"]
                baseline = self.run_hook([], stdin_text=json.dumps(expected))
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, baseline.stdout)
                expected["tool_input"]["command"] = "actx " + command
                self.assertEqual(
                    json.loads(p.stdout)["hookSpecificOutput"]["updatedInput"],
                    expected["tool_input"],
                )

    def test_only_nonempty_top_level_string_marker_selects_codex(self):
        # Two commands tell the two policies apart: `git status` rewrites
        # identically either way, while `git commit -m x` is empty under the
        # codex mutator policy and allow+updatedInput under the default one.
        # An invalid marker must leave the default output intact, so the
        # commit row proves the marker was NOT selected.
        for command in ("git status", "git commit -m x"):
            unmarked = json.loads(hook_input("Bash", {"command": command}))
            payloads = [unmarked]
            for marker in (None, "", False, True, 0, 1, [], {}, ["synthetic-turn"]):
                payloads.append({**unmarked, "turn_id": marker})
            payloads.append({**unmarked, "model": "synthetic-model"})
            payloads.append({**unmarked, "tool_input": {
                "command": command, "turn_id": "synthetic-turn",
            }})
            for payload in payloads:
                with self.subTest(command=command, payload=payload):
                    baseline = dict(payload)
                    baseline.pop("turn_id", None)
                    p = self.run_hook([], stdin_text=json.dumps(payload))
                    expected = self.run_hook([], stdin_text=json.dumps(baseline))
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertEqual(p.stdout, expected.stdout)
                    self.assertEqual(
                        json.loads(p.stdout)["hookSpecificOutput"]["updatedInput"]["command"],
                        "actx " + command,
                    )

    def test_explicit_agent_overrides_codex_marker(self):
        for agent in ("opencode", "devin", "pi"):
            for command in (PUSH, FORCE_PUSH, "git status"):
                with self.subTest(agent=agent, command=command):
                    args = ["--agent", agent]
                    p = self.run_hook(args, stdin_text=self.codex_payload(command))
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertEqual(p.stdout, self.hook_stdout(args, command))

    def test_explicit_codex_agent_supported_without_marker(self):
        # A codex mutator stays empty (defer) with no turn_id in the payload.
        self.assertEqual(self.hook_stdout(["--agent", "codex"], FALLBACK_MUTATOR),
                         "")
        for command in (FORCE_PUSH, "cat .env", "git status"):
            with self.subTest(command=command):
                self.assertEqual(self.hook_stdout(["--agent", "codex"], command),
                                 self.hook_stdout([], command))

    def test_codex_gate_verdicts_byte_identical(self):
        for command in (FORCE_PUSH, "git fetch --upload-pack='touch x' .",
                        "cat .env", "git add probe.txt && sudo rm -rf /"):
            with self.subTest(command=command):
                p = self.run_hook([], stdin_text=self.codex_payload(command))
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, self.hook_stdout([], command))
                self.assertIn(
                    json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"],
                    ("ask", "deny"),
                )

    def test_gate_runs_before_codex_mutator_deferral(self):
        from actx_lib import hook, security_gate

        # A rewritable mutator must still emit a gate veto. This catches
        # moving deferral ahead of the gate even for ordinary git commits.
        payload = self.codex_payload("git commit -m probe")
        for decision in ("deny", "ask"):
            with self.subTest(decision=decision):
                verdict = security_gate.SecurityDecision(decision, "probe reason", "T_PROBE")
                with mock.patch.object(security_gate, "evaluate_security", return_value=verdict) as gate:
                    result = hook.process(payload)
                gate.assert_called_once_with("git commit -m probe")
                reason = ("actx security gate violation [T_PROBE]: probe reason"
                          if decision == "deny" else
                          "actx security gate confirmation required [T_PROBE] "
                          "'git commit -m probe': runs a command class that "
                          "the security gate asks a human to review — "
                          "probe reason")
                self.assertEqual(result, {"hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": decision,
                    "permissionDecisionReason": reason,
                }})

    def test_codex_gate_exception_defers_before_rewriter_on_benign_command(self):
        # Pins two things on a benign command: the gate failure still
        # defers (empty output, no ask) and the deferral happens BEFORE the
        # rewriter, so no rewritten command is emitted. The irreversible
        # gate-error ask is pinned in Tk70GateErrorAskTests.
        from actx_lib import hook

        out = io.StringIO()
        with mock.patch("actx_lib.security_gate.evaluate_security",
                        side_effect=RuntimeError("probe failure")), \
             mock.patch("actx_lib.rewriter.rewrite") as rewrite, \
             mock.patch("sys.stdin", io.StringIO(self.codex_payload("ls -la"))), \
             mock.patch("sys.stdout", out):
            rc = hook.main()
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), "")
        rewrite.assert_not_called()


# TK-70 STEP-04 (plan REQ-01/REQ-04): an ordinary push gets no verdict from
# actx on any agent, and a gate failure asks instead of failing open on an
# irreversible command.
PUSH_UNPROTECTED = "git push origin feature"
PUSH_PROTECTED = "git push origin main"
PROTECTED_PUSH_REASON = "Pushing to protected branch 'main' requires human confirmation"
GATE_ERROR_MESSAGE = "actx security gate internal error on irreversible command"
GATE_ERROR_EXPLANATION = ("the security gate could not finish checking this "
                          "command, so it needs a human decision")
AGY_PUSH_ASK = {
    "decision": "ask",
    "reason": "actx: command outside actx policy — deferred to user confirmation",
}


def gate_error_ask(message):
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "permissionDecisionReason": (
            "actx security gate confirmation required [T6_GATE_ERROR] "
            f"'{PUSH_UNPROTECTED}': {GATE_ERROR_EXPLANATION} "
            f"(internal error: {message}) — {GATE_ERROR_MESSAGE}: {message}"
        ),
    }}


class Tk70PushPolicyTests(unittest.TestCase):
    run_hook = HookAgentPolicyTests.run_hook
    hook_stdout = HookAgentPolicyTests.hook_stdout

    def assert_empty(self, args, command):
        p = self.run_hook(args, command)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "")

    def test_unprotected_push_defers_on_every_claude_schema_agent(self):
        for agent in (None, "codex", "opencode", "devin", "pi",
                      "hermes", "dsh"):
            args = [] if agent is None else ["--agent", agent]
            with self.subTest(agent=agent):
                self.assert_empty(args, PUSH_UNPROTECTED)

    def test_unprotected_push_defers_for_codex_turn_id_marker(self):
        payload = json.dumps({
            "turn_id": "synthetic-turn",
            "tool_name": "Bash",
            "tool_input": {"command": PUSH_UNPROTECTED},
        })
        p = self.run_hook([], stdin_text=payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "")

    def test_antigravity_unprotected_push_falls_through_to_ask(self):
        payload = gemini_input("run_command", {"CommandLine": PUSH_UNPROTECTED})
        p = self.run_hook([], stdin_text=payload)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout), AGY_PUSH_ASK)

    def test_other_git_mutators_keep_previous_policy(self):
        for command in ("git add probe.txt", "git commit -m probe",
                        "git pull", "git fetch"):
            with self.subTest(command=command):
                base = json.loads(self.hook_stdout([], command))
                output = base["hookSpecificOutput"]
                self.assertEqual(output["permissionDecision"], "allow")
                self.assertEqual(output["updatedInput"],
                                 {"command": "actx " + command})
                self.assert_empty(["--agent", "codex"], command)
                self.assert_empty(["--agent", "opencode"], command)
                self.assert_empty(["--agent", "hermes"], command)
                self.assert_empty(["--agent", "dsh"], command)
                self.assertEqual(
                    json.loads(self.hook_stdout(["--agent", "devin"], command)),
                    DEVIN_MUTATOR_ALLOW)
                self.assertEqual(self.hook_stdout(["--agent", "pi"], command),
                                 self.hook_stdout([], command))
                agy = self.run_hook([], stdin_text=gemini_input(
                    "run_command", {"CommandLine": command}))
                self.assertEqual(json.loads(agy.stdout), {
                    "decision": "allow",
                    "overwrite": {"CommandLine": "actx " + command},
                })

    def test_dangerous_push_forms_keep_gate_verdicts(self):
        reasons = {
            "git push --tags origin feature":
                "git push --tags deletes or mass-updates remote refs and "
                "requires human confirmation",
            "git push --delete origin feature":
                "git push --delete deletes or mass-updates remote refs and "
                "requires human confirmation",
            "git push --mirror origin":
                "git push --mirror deletes or mass-updates remote refs and "
                "requires human confirmation",
            "git push origin :feature":
                "Deleting a remote ref via a ':dst' refspec requires human "
                "confirmation",
            PUSH_PROTECTED: PROTECTED_PUSH_REASON,
        }
        for command, reason in reasons.items():
            with self.subTest(command=command):
                for agent in (None, "codex", "devin"):
                    args = [] if agent is None else ["--agent", agent]
                    self.assertEqual(json.loads(self.hook_stdout(args, command)), {
                        "hookSpecificOutput": {
                            "hookEventName": "PreToolUse",
                            "permissionDecision": "ask",
                            "permissionDecisionReason": (
                                "actx security gate confirmation required "
                                f"[T6_HIGH_RISK_GIT] {shlex.quote(command)}: "
                                f"{GIT_EXPLANATION} — {reason}"
                            ),
                        }
                    })
                for agent in ("opencode", "pi"):
                    with self.subTest(command=command, agent=agent):
                        self.assertEqual(
                            json.loads(self.hook_stdout(
                                ["--agent", agent], command)),
                            gate_ask_as_deny(agent, "T6_HIGH_RISK_GIT", reason))
                agy = self.run_hook([], stdin_text=gemini_input(
                    "run_command", {"CommandLine": command}))
                self.assertEqual(json.loads(agy.stdout), {
                    "decision": "force_ask",
                    "reason": (
                        "actx security gate confirmation required "
                        f"[T6_HIGH_RISK_GIT] {shlex.quote(command)}: "
                        f"{GIT_EXPLANATION} — {reason}"),
                })


class Tk70GateErrorAskTests(unittest.TestCase):
    run_hook = HookAgentPolicyTests.run_hook

    def main_stdout(self, args, payload, effect):
        from actx_lib import hook

        out = io.StringIO()
        with mock.patch("actx_lib.security_gate.evaluate_security",
                        side_effect=effect), \
             mock.patch("sys.stdin", io.StringIO(payload)), \
             mock.patch("sys.stdout", out):
            rc = hook.main(list(args))
        self.assertEqual(rc, 0)
        return out.getvalue()

    def test_gate_runtime_error_asks_on_unprotected_push(self):
        payload = hook_input("Bash", {"command": PUSH_UNPROTECTED})
        expected = gate_error_ask("boom")
        for args in ([], ["--agent", "codex"], ["--agent", "devin"],
                     ["--agent", "dsh"]):
            with self.subTest(args=args):
                self.assertEqual(
                    json.loads(self.main_stdout(args, payload, RuntimeError("boom"))),
                    expected)
        for agent in ("opencode", "pi"):
            with self.subTest(agent=agent):
                self.assertEqual(
                    json.loads(self.main_stdout(
                        ["--agent", agent], payload, RuntimeError("boom"))),
                    gate_ask_as_deny(agent, "T6_GATE_ERROR",
                                     f"{GATE_ERROR_MESSAGE}: boom"))

    def test_hermes_gate_error_approves_on_unprotected_push(self):
        # Hermes has its own ask shape ({"action": "approve", ...}), so the
        # shared claude-schema loop above must not carry this agent.
        payload = hook_input("terminal", {"command": PUSH_UNPROTECTED})
        self.assertEqual(
            json.loads(self.main_stdout(
                ["--agent", "hermes"], payload, RuntimeError("boom"))),
            {"action": "approve",
             "message": (
                 "actx security gate confirmation required [T6_GATE_ERROR] "
                 f"'{PUSH_UNPROTECTED}': {GATE_ERROR_EXPLANATION} "
                 f"(internal error: boom) — {GATE_ERROR_MESSAGE}: boom")})

    def test_antigravity_gate_runtime_error_force_asks_on_unprotected_push(self):
        payload = gemini_input("run_command", {"CommandLine": PUSH_UNPROTECTED})
        self.assertEqual(
            json.loads(self.main_stdout([], payload, RuntimeError("boom"))),
            {"decision": "force_ask",
             "reason": (
                 "actx security gate confirmation required [T6_GATE_ERROR] "
                 f"'{PUSH_UNPROTECTED}': {GATE_ERROR_EXPLANATION} "
                 f"(internal error: boom) — {GATE_ERROR_MESSAGE}: boom")})

    def test_gate_runtime_error_keeps_fail_open_on_ro_command(self):
        payload = hook_input("Bash", {"command": "ls"})
        for args in ([], ["--agent", "opencode"], ["--agent", "pi"]):
            with self.subTest(args=args):
                self.assertEqual(
                    self.main_stdout(args, payload, RuntimeError("boom")), "")
        agy = gemini_input("run_command", {"CommandLine": "ls"})
        self.assertEqual(self.main_stdout([], agy, RuntimeError("boom")), "")

    def test_engine_value_error_asks_on_irreversible_chunk(self):
        from actx_lib import security_gate

        with mock.patch("actx_lib.security_gate.engine._check_high_risk_tools",
                        side_effect=ValueError("bad pattern")):
            result = security_gate.evaluate_security("helm install r c")
        self.assertEqual(result.decision, "ask")
        self.assertEqual(result.category, "T6_GATE_ERROR")
        self.assertEqual(result.reason,
                         f"{GATE_ERROR_MESSAGE}: bad pattern")

    def test_engine_value_error_keeps_allow_on_ro_command(self):
        from actx_lib import security_gate

        with mock.patch("actx_lib.security_gate.engine._check_high_risk_tools",
                        side_effect=ValueError("bad pattern")):
            result = security_gate.evaluate_security("ls")
        self.assertEqual(result.decision, "allow")

    def test_engine_outer_error_asks_on_irreversible_command(self):
        from actx_lib import security_gate

        with mock.patch("actx_lib.security_gate.engine._closed_grammar_words",
                        side_effect=RuntimeError("boom")):
            result = security_gate.evaluate_security("helm install r c")
        self.assertEqual(result.decision, "ask")
        self.assertEqual(result.category, "T6_GATE_ERROR")
        self.assertEqual(result.reason, f"{GATE_ERROR_MESSAGE}: boom")

    def test_engine_outer_error_keeps_allow_on_ro_command(self):
        from actx_lib import security_gate

        with mock.patch("actx_lib.security_gate.engine._closed_grammar_words",
                        side_effect=RuntimeError("boom")):
            result = security_gate.evaluate_security("ls")
        self.assertEqual(result.decision, "allow")

    def test_invalid_input_still_no_op(self):
        from actx_lib import hook

        for text in ("not json",
                     json.dumps({"tool_input": {"command": PUSH_UNPROTECTED}})):
            with self.subTest(text=text):
                out = io.StringIO()
                with mock.patch("sys.stdin", io.StringIO(text)), \
                     mock.patch("sys.stdout", out):
                    rc = hook.main([])
                self.assertEqual(rc, 0)
                self.assertEqual(out.getvalue(), "")


# TK-69 STEP-01 (plan REQ-01/REQ-06): Hermes shell-hook output. The agent
# sends {"tool_name": "terminal", ...}; every verdict on the claude-schema
# path is a flat shape - block / approve / modify - and a defer is empty
# stdout with exit 0 (the Hermes no-op).
class HermesPolicyTests(unittest.TestCase):
    run_hook = HookAgentPolicyTests.run_hook

    TOOL = "terminal"

    def run_hermes(self, command=None, stdin_text=None):
        if stdin_text is None:
            stdin_text = hook_input(self.TOOL, {"command": command})
        return self.run_hook(["--agent", "hermes"], stdin_text=stdin_text)

    def hermes_stdout(self, command):
        p = self.run_hermes(command)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def assert_empty(self, command):
        p = self.run_hermes(command)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "")

    def test_gate_deny_blocks(self):
        self.assertEqual(json.loads(self.hermes_stdout("cat .env")), {
            "decision": "block",
            "reason": (
                "actx security gate violation [T1_CREDENTIAL_ACCESS]: "
                "Access to sensitive credential/file '.env' is prohibited"),
        })

    def test_gate_ask_approves(self):
        self.assertEqual(json.loads(self.hermes_stdout(FORCE_PUSH)), {
            "action": "approve",
            "message": (
                "actx security gate confirmation required [T6_HIGH_RISK_GIT] "
                f"{shlex.quote(FORCE_PUSH)}: {GIT_EXPLANATION} — "
                + FORCE_PUSH_REASON),
        })

    def test_observational_rewrite_modifies_without_context(self):
        data = json.loads(self.hermes_stdout("git log --oneline -5"))
        self.assertEqual(data, {
            "decision": "modify",
            "tool_input": {"command": "actx git log --oneline -5"},
        })
        self.assertNotIn("additionalContext", data)
        self.assertNotIn("hookSpecificOutput", data)

    def test_mutator_and_push_defer_empty(self):
        for command in ("git add x", "git push", PUSH_UNPROTECTED):
            with self.subTest(command=command):
                self.assert_empty(command)

    def test_gate_exception_defers_on_benign_command(self):
        # Mirrors the claude-schema fail-open half of TK-70 REQ-04.
        from actx_lib import hook

        out = io.StringIO()
        with mock.patch("actx_lib.security_gate.evaluate_security",
                        side_effect=RuntimeError("boom")), \
             mock.patch("sys.stdin", io.StringIO(hook_input(
                 self.TOOL, {"command": "ls -la"}))), \
             mock.patch("sys.stdout", out):
            rc = hook.main(["--agent", "hermes"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue(), "")

    def test_gate_exception_approves_on_unprotected_push(self):
        # T6_GATE_ERROR flows through the same mapping as a gate ask.
        from actx_lib import hook

        out = io.StringIO()
        with mock.patch("actx_lib.security_gate.evaluate_security",
                        side_effect=RuntimeError("boom")), \
             mock.patch("sys.stdin", io.StringIO(hook_input(
                 self.TOOL, {"command": PUSH_UNPROTECTED}))), \
             mock.patch("sys.stdout", out):
            rc = hook.main(["--agent", "hermes"])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue()), {
            "action": "approve",
            "message": (
                "actx security gate confirmation required [T6_GATE_ERROR] "
                f"'{PUSH_UNPROTECTED}': {GATE_ERROR_EXPLANATION} "
                f"(internal error: boom) — {GATE_ERROR_MESSAGE}: boom"),
        })

    def test_malformed_input_defers_empty(self):
        for text in (
            "{not json",
            json.dumps({"tool_input": {"command": "git status"}}),
            hook_input("Read", {"command": "git status"}),
            json.dumps({"tool_name": self.TOOL, "tool_input": "git status"}),
            hook_input(self.TOOL, {"description": "no command"}),
        ):
            with self.subTest(text=text):
                p = self.run_hermes(stdin_text=text)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, "")

    def test_internal_exception_escapes_process(self):
        # Internal actx failure must never look like a successful no-op.
        # Live probe (2026-11-09): mocking rewriter.is_git_push escapes
        # hook.process through _push_defers (it is called only after a true
        # is_mutator), and the actx entrypoint has no catch-all, so a real
        # Hermes run exits non-zero.
        from actx_lib import hook

        out = io.StringIO()
        with mock.patch("actx_lib.rewriter.is_git_push",
                        side_effect=RuntimeError("probe failure")), \
             mock.patch("sys.stdin", io.StringIO(hook_input(
                 self.TOOL, {"command": "git commit -m x"}))), \
             mock.patch("sys.stdout", out):
            with self.assertRaises(RuntimeError):
                hook.main(["--agent", "hermes"])
        self.assertEqual(out.getvalue(), "")

    def test_main_level_stdin_oserror_exits_nonzero(self):
        # Live probe (2026-11-09): a write-only stdin fd makes sys.stdin.read
        # raise OSError in main (:292-304) - rc 1, empty stdout.
        with tempfile.NamedTemporaryFile() as f:
            fd = os.open(f.name, os.O_WRONLY)
            try:
                p = subprocess.run(
                    [ACTX, "hook", "--agent", "hermes"],
                    stdin=fd, capture_output=True, text=True)
            finally:
                os.close(fd)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")
        self.assertIn("failed to read stdin", p.stderr)


# TK-72 STEP-01 (plan REQ-02/REQ-06): dsh is gate-only. The gate deny/ask
# passes through in the claude schema (the mjs adapter maps it to dsh
# verdicts); nothing else is ever emitted - no allow, no updatedInput.
class DshPolicyTests(unittest.TestCase):
    run_hook = HookAgentPolicyTests.run_hook
    hook_stdout = HookAgentPolicyTests.hook_stdout

    def run_dsh(self, command=None, stdin_text=None):
        if stdin_text is None:
            stdin_text = hook_input("bash", {"command": command})
        return self.run_hook(["--agent", "dsh"], stdin_text=stdin_text)

    def dsh_stdout(self, command):
        p = self.run_dsh(command)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def assert_empty(self, command):
        p = self.run_dsh(command)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, "")

    def test_gate_deny_is_claude_schema(self):
        self.assertEqual(self.dsh_stdout("cat .env"),
                         self.hook_stdout([], "cat .env"))
        self.assertEqual(json.loads(self.dsh_stdout("cat .env")), {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "actx security gate violation [T1_CREDENTIAL_ACCESS]: "
                    "Access to sensitive credential/file '.env' is prohibited"),
            }
        })

    def test_gate_ask_is_claude_schema(self):
        self.assertEqual(self.dsh_stdout(FORCE_PUSH),
                         self.hook_stdout([], FORCE_PUSH))
        self.assertEqual(json.loads(self.dsh_stdout(FORCE_PUSH)), {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": (
                    "actx security gate confirmation required "
                    f"[T6_HIGH_RISK_GIT] {shlex.quote(FORCE_PUSH)}: "
                    f"{GIT_EXPLANATION} — " + FORCE_PUSH_REASON),
            }
        })

    def test_observational_rewrite_never_emits_updated_input(self):
        self.assert_empty("git log --oneline -5")

    def test_mutator_and_push_defer_empty(self):
        for command in ("git add x", "git push", PUSH_UNPROTECTED):
            with self.subTest(command=command):
                self.assert_empty(command)

    def test_gate_error_asks_on_unprotected_push(self):
        from actx_lib import hook

        out = io.StringIO()
        with mock.patch("actx_lib.security_gate.evaluate_security",
                        side_effect=RuntimeError("boom")), \
             mock.patch("sys.stdin", io.StringIO(hook_input(
                 "bash", {"command": PUSH_UNPROTECTED}))), \
             mock.patch("sys.stdout", out):
            rc = hook.main(["--agent", "dsh"])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue()), gate_error_ask("boom"))

    def test_malformed_input_defers_empty(self):
        for text in (
            "{not json",
            json.dumps({"tool_input": {"command": "git status"}}),
            hook_input("Read", {"command": "git status"}),
            json.dumps({"tool_name": "bash", "tool_input": "git status"}),
            hook_input("bash", {"description": "no command"}),
        ):
            with self.subTest(text=text):
                p = self.run_dsh(stdin_text=text)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, "")


def gate_ask_categories():
    """Every category the gate can emit with decision="ask", enumerated by
    the plan's three operands: SecurityDecision(decision="ask") categories
    in security_gate/*.py, the T6_ASK_TABLE/FAMILIES heads, and the heads
    passed to every `_t6_ask(` call site (the aws/az site passes `lookup`,
    so each literal the dispatch compares it with is a head)."""
    import ast
    import pathlib

    from actx_lib import cli_families
    from actx_lib import security_gate
    from actx_lib.security_gate import t6_tools

    package = pathlib.Path(security_gate.__file__).parent
    static = set()
    heads = set(t6_tools.T6_ASK_TABLE) | set(cli_families.FAMILIES)
    for path in sorted(package.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None)
            if name == "SecurityDecision":
                keywords = {kw.arg: kw.value for kw in node.keywords}
                decision = keywords.get("decision")
                category = keywords.get("category")
                if (isinstance(decision, ast.Constant)
                        and decision.value == "ask"
                        and isinstance(category, ast.Constant)):
                    static.add(category.value)
            elif name == "_t6_ask" and node.args:
                head = node.args[0]
                if (isinstance(head, ast.Constant)
                        and isinstance(head.value, str)):
                    heads.add(head.value)
                elif isinstance(head, ast.Name):
                    for compare in ast.walk(tree):
                        if (not isinstance(compare, ast.Compare)
                                or not isinstance(compare.left, ast.Name)
                                or compare.left.id != head.id):
                            continue
                        for comparator in compare.comparators:
                            for element in getattr(comparator, "elts", ()):
                                if (isinstance(element, ast.Constant)
                                        and isinstance(element.value, str)):
                                    heads.add(element.value)
    family = {"T6_HIGH_RISK_" + head.upper() for head in heads}
    return static | family


class HumanAskReasonTests(unittest.TestCase):
    """Human gate-confirmation texts carry the command, a plain-language
    explanation and the gate rule reason; the deny and ask_as_deny texts
    stay byte-identical."""

    def test_every_gate_ask_category_has_an_explanation(self):
        from actx_lib import hook

        categories = gate_ask_categories()
        self.assertEqual(len(categories), 47, sorted(categories))
        for category in sorted(categories):
            with self.subTest(category=category):
                explanation = hook._explanation(category, "probe reason")
                self.assertTrue(explanation)
                self.assertNotEqual(explanation, hook._HUMAN_ASK_FALLBACK)
        self.assertEqual(
            hook._explanation("T6_HIGH_RISK_KUBECTL", "probe reason"),
            "runs kubectl in a mode that can change remote state, publish "
            "artifacts, or deploy a service")

    def test_unknown_category_falls_back_and_keeps_category_and_command(self):
        from actx_lib import hook

        self.assertEqual(
            hook._human_ask_message(
                "git commit -m probe", "T_SYNTHETIC", "probe reason"),
            "actx security gate confirmation required [T_SYNTHETIC] "
            "'git commit -m probe': runs a command class that the security "
            "gate asks a human to review — probe reason")

    def test_long_command_is_truncated_with_hidden_char_count(self):
        from actx_lib import hook

        command = "echo " + "x" * 120
        self.assertEqual(
            hook._human_ask_message(command, "T5_SUPPLY_CHAIN",
                                    "probe reason"),
            "actx security gate confirmation required [T5_SUPPLY_CHAIN] "
            "'echo " + "x" * 65 + "…(+15 chars)…" + "x" * 40 + "': "
            "installs or updates packages — third-party code will run on "
            "this machine — probe reason")

    def test_truncation_keeps_a_trailing_trigger_visible(self):
        from actx_lib import hook

        command = "echo " + "x" * 120 + " && git push --force origin main"
        output = hook.process(hook_input("Bash", {"command": command}))
        output = output["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "ask")
        reason = output["permissionDecisionReason"]
        self.assertIn("…(+47 chars)…", reason)
        self.assertIn("git push --force origin main", reason)
        self.assertTrue(reason.endswith("— " + FORCE_PUSH_REASON), reason)

    def test_hidden_compound_trigger_is_flagged_and_named_by_the_rule(self):
        from actx_lib import hook

        command = ("echo " + "A" * 65 + " && git push --force origin main"
                   " && echo " + "B" * 65)
        output = hook.process(hook_input("Bash", {"command": command}))
        output = output["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "ask")
        reason = output["permissionDecisionReason"]
        self.assertTrue(reason.startswith(
            "actx security gate confirmation required [T6_HIGH_RISK_GIT] "
            "'echo "), reason)
        self.assertIn(
            "…(+66 chars, compound command partially shown)…", reason)
        self.assertNotIn("git push --force origin main", reason)
        self.assertTrue(reason.endswith("— " + FORCE_PUSH_REASON), reason)

    def test_embedded_single_quote_stays_inside_the_shlex_boundary(self):
        from actx_lib import hook

        command = "git config alias.p '!id'"
        message = hook._human_ask_message(
            command, "T6_HIGH_RISK_GIT", "probe reason")
        prefix = ("actx security gate confirmation required "
                  "[T6_HIGH_RISK_GIT] ")
        self.assertTrue(
            message.startswith(prefix + shlex.quote(command) + ": "), message)
        quoted = message[len(prefix):message.index(": rewrites")]
        self.assertEqual(shlex.split(quoted), [command])

    def test_gate_error_exception_tail_is_printable_and_capped(self):
        from actx_lib import hook

        exc = "boom\nwith\rcontrol\tchars" + "z" * 200
        message = hook._human_ask_message(
            "git push origin feature", "T6_GATE_ERROR",
            GATE_ERROR_MESSAGE + ": " + exc)
        start = message.index("(internal error: ") + len("(internal error: ")
        tail = message[start:message.index(") — ", start)]
        self.assertEqual(len(tail), 120)
        self.assertTrue(tail.endswith("…"))
        self.assertTrue(tail.isprintable(), tail)
        self.assertEqual(len(message.rsplit(" — ", 1)[1]), 120)

    def test_ask_as_deny_is_byte_identical_across_runs(self):
        expected = json.dumps(gate_ask_as_deny(
            "opencode", "T6_HIGH_RISK_GIT", FORCE_PUSH_REASON)) + "\n"
        for _ in range(2):
            p = subprocess.run(
                [ACTX, "hook", "--agent", "opencode"],
                input=hook_input("Bash", {"command": FORCE_PUSH}),
                capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout, expected)


class Tk70PushPerfTests(unittest.TestCase):
    def test_warm_hook_process_push_under_1ms(self):
        import time

        from actx_lib import hook

        payload = hook_input("Bash", {"command": PUSH_UNPROTECTED})
        self.assertIsNone(hook.process(payload))  # warm-up
        best = None
        for _ in range(5):
            start = time.process_time()
            for _ in range(200):
                result = hook.process(payload)
            ms = (time.process_time() - start) / 200 * 1000.0
            best = ms if best is None else min(best, ms)
        self.assertIsNone(result)
        self.assertLess(best, 1.0, f"warm hook.process push {best:.4f}ms per op")


if __name__ == "__main__":
    unittest.main()
