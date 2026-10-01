import io
import json
import os
import subprocess
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
        self.assertIn("Force-pushing to remote git repository requires human confirmation", data["reason"])

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
        self.assertIn("alias.p", data["reason"])

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
        self.assertIn("unknown discovered file", output["permissionDecisionReason"])

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
PUSH = "git push origin main"
FORCE_PUSH = "git push --force origin main"
FORCE_PUSH_REASON = "Force-pushing to remote git repository requires human confirmation"
# Byte-exact HEAD b051058 (v2.12.0) output of `actx hook` for PUSH.
PUSH_NO_AGENT_STDOUT = (
    '{"hookSpecificOutput": {"hookEventName": "PreToolUse", '
    '"permissionDecision": "allow", "updatedInput": {"command": '
    '"actx git push origin main"}, "additionalContext": '
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

    # --- mutators -------------------------------------------------------
    def test_opencode_mutator_not_rewritten_empty(self):
        self.assertEqual(self.hook_stdout(["--agent", "opencode"], PUSH), "")

    def test_devin_mutator_allow_without_updated_input(self):
        out = self.hook_stdout(["--agent", "devin"], PUSH)
        self.assertEqual(out, json.dumps(DEVIN_MUTATOR_ALLOW) + "\n")

    def test_pi_mutator_rewritten(self):
        self.assertEqual(self.hook_stdout(["--agent", "pi"], PUSH),
                         PUSH_NO_AGENT_STDOUT)

    def test_no_agent_mutator_rewritten_byte_identical(self):
        self.assertEqual(self.hook_stdout([], PUSH), PUSH_NO_AGENT_STDOUT)

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
        for args in (["--agent", "nosuch"], ["--agent"], ["--bogus"],
                     ["--agent", "opencode", "--bogus"],
                     ["--bogus", "--agent", "opencode"]):
            with self.subTest(args=args):
                p = self.run_hook(args, PUSH)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, PUSH_NO_AGENT_STDOUT)

    # --- --payload (A1 fallback) ----------------------------------------
    def test_payload_either_order_matches_stdin_form(self):
        # stdin carries a different command: the payload must replace it.
        decoy = hook_input("Bash", {"command": "git log"})
        for command in (PUSH, FORCE_PUSH, "git status"):
            expected = self.hook_stdout(["--agent", "opencode"], command)
            payload = hook_input("Bash", {"command": command})
            for args in (["--agent", "opencode", "--payload", payload],
                         ["--payload", payload, "--agent", "opencode"]):
                with self.subTest(command=command, order=args[0]):
                    p = self.run_hook(args, stdin_text=decoy)
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertEqual(p.stdout, expected)
        self.assertEqual(self.hook_stdout(["--agent", "opencode"], PUSH), "")
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

    # --- gate exception -> no opinion, every agent ----------------------
    def test_gate_exception_empty_for_every_agent(self):
        from actx_lib import hook

        for args in ([], ["--agent", "opencode"], ["--agent", "devin"],
                     ["--agent", "pi"]):
            with self.subTest(args=args):
                out = io.StringIO()
                with mock.patch(
                    "actx_lib.security_gate.evaluate_security",
                    side_effect=RuntimeError("boom"),
                ), mock.patch(
                    "sys.stdin", io.StringIO(hook_input("Bash", {"command": PUSH}))
                ), mock.patch("sys.stdout", out):
                    rc = hook.main(args)
                self.assertEqual(rc, 0)
                self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
