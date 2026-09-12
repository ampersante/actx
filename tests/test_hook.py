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


if __name__ == "__main__":
    unittest.main()
