import json
import os
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")


def hook_input(tool_name, tool_input):
    return json.dumps({"tool_name": tool_name, "tool_input": tool_input})


class HookCliTests(unittest.TestCase):
    def run_hook(self, stdin_text):
        return subprocess.run(
            [ACTX, "hook"],
            input=stdin_text,
            capture_output=True,
            text=True,
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

    def test_safe_uncompressed_command_returns_empty_deferral(self):
        # kubectl apply is safe (not denied), but not rewritable -> strictly returns None (empty stdout)
        p = self.run_hook(hook_input("Bash", {"command": "kubectl apply -f f"}))
        self.assertEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")

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

    def test_actx_prefix_idempotent_empty(self):
        p = self.run_hook(hook_input("Bash", {"command": "actx git status"}))
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
