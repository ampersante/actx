import json
import os
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.realpath(os.path.join(ROOT, "actx"))

INSTRUCTION_SECTION = """## Output compression (actx)

To reduce context noise, prefix read-only commands with `actx`:
- `git status` → `actx git status`
- `git diff` → `actx git diff`
- `git log` → `actx git log`
- `ls` → `actx ls`
- `grep` → `actx grep`
- `find` → `actx find`

Mutating commands run normally. For full output, run the command without `actx` or use `actx --raw <command>`.
"""

AIDER_READ = "~/.config/actx/instructions.md"


class InitTests(unittest.TestCase):
    def run_actx(self, args, home):
        env = os.environ.copy()
        env["HOME"] = home
        return subprocess.run(
            [ACTX] + args,
            capture_output=True,
            text=True,
            env=env,
        )

    def handler(self):
        return {
            "type": "command",
            "command": shlex.quote(ACTX) + " hook",
            "timeout": 10,
        }

    def test_claude_double_init_single_entry_and_uninstall(self):
        with tempfile.TemporaryDirectory() as home:
            settings = os.path.join(home, ".claude", "settings.json")
            for _ in range(2):
                p = self.run_actx(["init", "--agent", "claude"], home)
                self.assertEqual(p.returncode, 0, p.stderr)
            with open(settings, encoding="utf-8") as handle:
                data = json.load(handle)
            entry = data["hooks"]["PreToolUse"][0]
            self.assertEqual(entry["matcher"], "Bash")
            self.assertEqual(len(entry["hooks"]), 1)
            self.assertEqual(entry["hooks"][0], self.handler())

            p = self.run_actx(["init", "--show"], home)
            self.assertIn("claude: installed", p.stdout)

            p = self.run_actx(["init", "--agent", "claude", "--uninstall"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(settings, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertNotIn("hooks", data)

    def test_codex_install_uninstall_preserves_other_hook(self):
        with tempfile.TemporaryDirectory() as home:
            hooks_file = os.path.join(home, ".codex", "hooks.json")
            os.makedirs(os.path.dirname(hooks_file), exist_ok=True)
            with open(hooks_file, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "matcher": "Bash",
                                    "hooks": [
                                        {
                                            "type": "command",
                                            "command": "echo existing",
                                        }
                                    ],
                                }
                            ]
                        }
                    },
                    handle,
                )
            p = self.run_actx(["init", "--agent", "codex"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            p = self.run_actx(["init", "--agent", "codex"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(hooks_file, encoding="utf-8") as handle:
                data = json.load(handle)
            hooks = data["hooks"]["PreToolUse"][0]["hooks"]
            self.assertEqual(len(hooks), 2)
            self.assertIn(self.handler(), hooks)

            p = self.run_actx(["init", "--agent", "codex", "--uninstall"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(hooks_file, encoding="utf-8") as handle:
                data = json.load(handle)
            hooks = data["hooks"]["PreToolUse"][0]["hooks"]
            self.assertEqual(len(hooks), 1)
            self.assertNotIn(self.handler(), hooks)

    def test_claude_non_json_settings_exit_1_unchanged(self):
        with tempfile.TemporaryDirectory() as home:
            settings = os.path.join(home, ".claude", "settings.json")
            os.makedirs(os.path.dirname(settings), exist_ok=True)
            original = '{\n  // comment\n  "hooks": {}\n}\n'
            with open(settings, "w", encoding="utf-8") as handle:
                handle.write(original)
            p = self.run_actx(["init", "--agent", "claude"], home)
            self.assertEqual(p.returncode, 1)
            self.assertNotEqual(p.stderr, "")
            with open(settings, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), original)

    def test_opencode_template_checks(self):
        with tempfile.TemporaryDirectory() as home:
            p = self.run_actx(["init", "--agent", "opencode"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            plugin = os.path.join(home, ".config", "opencode", "plugins", "actx.ts")
            with open(plugin, encoding="utf-8") as handle:
                content = handle.read()
            self.assertNotIn("__ACTX_ABS_PATH__", content)
            self.assertIn("tool.execute.before", content)
            self.assertIn("execFileSync", content)
            self.assertIn('["rewrite", cmd]', content)
            self.assertIn("catch", content)

            match = re.search(r"const ACTX = (.*)", content)
            self.assertIsNotNone(match)
            value = match.group(1).strip()
            self.assertTrue(value.startswith('"') and value.endswith('"'))
            substituted = json.loads(value)
            self.assertTrue(os.path.isabs(substituted))
            self.assertEqual(os.path.realpath(substituted), ACTX)

            p = self.run_actx(["init", "--agent", "opencode", "--uninstall"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertFalse(os.path.exists(plugin))

    def test_tier2_verbatim_and_dedupe(self):
        for agent in ("grok", "cline", "windsurf"):
            with self.subTest(agent=agent):
                with tempfile.TemporaryDirectory() as home:
                    p = self.run_actx(["init", "--agent", agent], home)
                    self.assertEqual(p.returncode, 0, p.stderr)
                    p = self.run_actx(["init", "--agent", agent], home)
                    self.assertEqual(p.returncode, 0, p.stderr)

                    if agent == "grok":
                        path = os.path.join(home, ".grok", "rules", "actx.md")
                    elif agent == "cline":
                        path = os.path.join(home, ".cline", "rules", "actx.md")
                    else:
                        path = os.path.join(
                            home,
                            ".codeium",
                            "windsurf",
                            "memories",
                            "global_rules.md",
                        )
                    with open(path, encoding="utf-8") as handle:
                        content = handle.read()
                    self.assertIn(INSTRUCTION_SECTION, content)
                    self.assertEqual(content.count("## Output compression (actx)"), 1)

                    p = self.run_actx(["init", "--agent", agent, "--uninstall"], home)
                    self.assertEqual(p.returncode, 0, p.stderr)
                    with open(path, encoding="utf-8") as handle:
                        content = handle.read()
                    self.assertNotIn("## Output compression (actx)", content)

    def test_aider_scalar_other_becomes_list(self):
        with tempfile.TemporaryDirectory() as home:
            conf = os.path.join(home, ".aider.conf.yml")
            os.makedirs(os.path.dirname(conf), exist_ok=True)
            with open(conf, "w", encoding="utf-8") as handle:
                handle.write("read: ~/other.md\n")

            p = self.run_actx(["init", "--agent", "aider"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            p = self.run_actx(["init", "--agent", "aider"], home)
            self.assertEqual(p.returncode, 0, p.stderr)

            with open(conf, encoding="utf-8") as handle:
                content = handle.read()
            self.assertIn("~/other.md", content)
            self.assertIn(AIDER_READ, content)
            self.assertEqual(content.count(AIDER_READ), 1)

            instructions = os.path.join(home, ".config", "actx", "instructions.md")
            with open(instructions, encoding="utf-8") as handle:
                self.assertIn(INSTRUCTION_SECTION, handle.read())

    def test_aider_list_form_deduped(self):
        with tempfile.TemporaryDirectory() as home:
            conf = os.path.join(home, ".aider.conf.yml")
            os.makedirs(os.path.dirname(conf), exist_ok=True)
            with open(conf, "w", encoding="utf-8") as handle:
                handle.write("read: [%s, ~/other.md]\n" % AIDER_READ)

            p = self.run_actx(["init", "--agent", "aider"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(conf, encoding="utf-8") as handle:
                content = handle.read()
            self.assertEqual(content.count(AIDER_READ), 1)
            self.assertIn("~/other.md", content)

            p = self.run_actx(["init", "--agent", "aider", "--uninstall"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(conf, encoding="utf-8") as handle:
                content = handle.read()
            self.assertNotIn(AIDER_READ, content)
            self.assertIn("~/other.md", content)

    def test_aider_scalar_own_deduped_and_uninstall_removes_key(self):
        with tempfile.TemporaryDirectory() as home:
            conf = os.path.join(home, ".aider.conf.yml")
            os.makedirs(os.path.dirname(conf), exist_ok=True)
            with open(conf, "w", encoding="utf-8") as handle:
                handle.write("read: %s\n" % AIDER_READ)

            p = self.run_actx(["init", "--agent", "aider"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(conf, encoding="utf-8") as handle:
                content = handle.read()
            self.assertEqual(content.count(AIDER_READ), 1)

            p = self.run_actx(["init", "--agent", "aider", "--uninstall"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(conf, encoding="utf-8") as handle:
                content = handle.read()
            self.assertNotIn("read:", content)

    def test_cursor_writes_nothing_and_prints_section(self):
        with tempfile.TemporaryDirectory() as home:
            p = self.run_actx(["init", "--agent", "cursor"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn(INSTRUCTION_SECTION, p.stdout)
            entries = os.listdir(home)
            self.assertEqual(entries, [])

    def test_autodetect_only_existing(self):
        with tempfile.TemporaryDirectory() as home:
            claude_dir = os.path.join(home, ".claude")
            os.makedirs(claude_dir, exist_ok=True)
            grok_dir = os.path.join(home, ".grok")
            os.makedirs(grok_dir, exist_ok=True)

            p = self.run_actx(["init"], home)
            self.assertEqual(p.returncode, 0, p.stderr)

            self.assertTrue(os.path.exists(os.path.join(home, ".claude", "settings.json")))
            self.assertFalse(os.path.exists(os.path.join(home, ".codex", "hooks.json")))
            self.assertFalse(
                os.path.exists(os.path.join(home, ".config", "opencode", "plugins", "actx.ts"))
            )
            grok_rules = os.path.join(home, ".grok", "rules", "actx.md")
            with open(grok_rules, encoding="utf-8") as handle:
                self.assertIn(INSTRUCTION_SECTION, handle.read())

    def test_agent_all_installs_everything(self):
        with tempfile.TemporaryDirectory() as home:
            p = self.run_actx(["init", "--agent", "all"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn(INSTRUCTION_SECTION, p.stdout)

            for path in (
                os.path.join(home, ".claude", "settings.json"),
                os.path.join(home, ".codex", "hooks.json"),
                os.path.join(home, ".config", "opencode", "plugins", "actx.ts"),
                os.path.join(home, ".grok", "rules", "actx.md"),
                os.path.join(home, ".cline", "rules", "actx.md"),
                os.path.join(home, ".codeium", "windsurf", "memories", "global_rules.md"),
                os.path.join(home, ".config", "actx", "instructions.md"),
                os.path.join(home, ".aider.conf.yml"),
            ):
                self.assertTrue(os.path.exists(path), path)

            p = self.run_actx(["init", "--show"], home)
            for agent in (
                "claude",
                "codex",
                "opencode",
                "grok",
                "cline",
                "windsurf",
                "aider",
            ):
                self.assertIn("%s: installed" % agent, p.stdout)
            self.assertIn("cursor: manual (cursor)", p.stdout)

    def test_gemini_double_init_single_entry_and_uninstall(self):
        with tempfile.TemporaryDirectory() as home:
            settings = os.path.join(home, ".gemini", "settings.json")
            for _ in range(2):
                p = self.run_actx(["init", "--agent", "gemini"], home)
                self.assertEqual(p.returncode, 0, p.stderr)
            with open(settings, encoding="utf-8") as handle:
                data = json.load(handle)
            entry = data["hooks"]["BeforeTool"][0]
            self.assertEqual(entry["matcher"], "Bash")
            self.assertEqual(len(entry["hooks"]), 1)
            self.assertEqual(entry["hooks"][0], self.handler())

            p = self.run_actx(["init", "--agent", "gemini", "--uninstall"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(settings, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertNotIn("hooks", data)

    def test_copilot_install_preserves_existing_hook_and_uninstall(self):
        with tempfile.TemporaryDirectory() as home:
            settings = os.path.join(home, ".copilot", "settings.json")
            os.makedirs(os.path.dirname(settings), exist_ok=True)
            with open(settings, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "hooks": {
                            "preToolUse": [
                                {"type": "command", "bash": "echo existing"}
                            ]
                        }
                    },
                    handle,
                )
            p = self.run_actx(["init", "--agent", "copilot"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            p = self.run_actx(["init", "--agent", "copilot"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(settings, encoding="utf-8") as handle:
                data = json.load(handle)
            pretool = data["hooks"]["preToolUse"]
            self.assertEqual(len(pretool), 2)

            p = self.run_actx(["init", "--agent", "copilot", "--uninstall"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(settings, encoding="utf-8") as handle:
                data = json.load(handle)
            pretool = data["hooks"]["preToolUse"]
            self.assertEqual(len(pretool), 1)
            self.assertEqual(pretool[0]["bash"], "echo existing")

    def test_gemini_non_json_settings_exit_1_unchanged(self):
        with tempfile.TemporaryDirectory() as home:
            settings = os.path.join(home, ".gemini", "settings.json")
            os.makedirs(os.path.dirname(settings), exist_ok=True)
            original = '{\n  "hooks": [broken\n}\n'
            with open(settings, "w", encoding="utf-8") as handle:
                handle.write(original)
            p = self.run_actx(["init", "--agent", "gemini"], home)
            self.assertEqual(p.returncode, 1)
            with open(settings, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), original)

    def test_unknown_agent_exit_1(self):
        with tempfile.TemporaryDirectory() as home:
            p = self.run_actx(["init", "--agent", "bogus"], home)
            self.assertEqual(p.returncode, 1)
            self.assertIn("unknown agent", p.stderr)


if __name__ == "__main__":
    unittest.main()
