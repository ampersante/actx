import io
import json
import os
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

from actx_lib import installer
from actx_lib.installer import INSTRUCTION_SECTION

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.realpath(os.path.join(ROOT, "actx"))

_STALE_SECTION = """## Output compression (actx)

To reduce context noise, prefix read-only commands with `actx`:
- `git status` → `actx git status`
- `ls` → `actx ls`

Mutating commands run normally. For full output, run the command without `actx` or use `actx --raw <command>`.
"""

# The v2.8.0 (TK-51) section body: package-manager discipline present,
# compact-flags table absent - the pre-TK-45 form.
_PRE_TK45_SECTION = """## Output compression (actx)

To reduce context noise, prefix supported shell commands with `actx`:
- `git status` → `actx git status`
- `git diff` → `actx git diff`
- `git log` → `actx git log`
- `git show` / `git blame` → `actx git show` / `actx git blame`
- `ls` / `ls -la` → `actx ls` / `actx ls -la`
- `grep` / `rg` → `actx grep` / `actx rg`
- `find` / `cat` / `tree` → `actx find` / `actx cat` / `actx tree`
- `pytest` / `ruff` / `docker ps` / `gh pr list` → `actx <cmd>`
- `vercel whoami` / `railway status` / `wrangler deployments list` / `gcloud projects list` → `actx <cmd>`

Hook/plugin agents rewrite automatically when installed. For full output, run without `actx` or use `actx --raw <command>`.

Package manager discipline:
- Package installations always require human confirmation (ask) — never attempt to bypass it.
- Prefer lockfile-strict forms (`npm ci` / `pnpm install --frozen-lockfile` / `uv sync --frozen`); avoid `latest`.
- Do not switch the project's package manager on your own initiative.
"""


def isolated_env(home, extra=None):
    """HOME=<tmp>; agent-dir overrides from the caller's environment are
    dropped so no test can reach a real config through them."""
    env = os.environ.copy()
    env["HOME"] = home
    env.pop("XDG_CONFIG_HOME", None)
    env.pop("PI_CODING_AGENT_DIR", None)
    env.update(extra or {})
    return env


class InitTests(unittest.TestCase):
    def run_actx(self, args, home):
        env = isolated_env(home)
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
            # TK-58: the user's entry is never mutated; actx owns its own
            # entry, found by handler command.
            entries = data["hooks"]["PreToolUse"]
            self.assertEqual(entries[0]["matcher"], "Bash")
            self.assertEqual(len(entries[0]["hooks"]), 1)
            self.assertNotIn(self.handler(), entries[0]["hooks"])
            self.assertEqual(len(entries), 2)
            self.assertEqual(entries[1]["matcher"], "Bash|shell|bash|exec")
            self.assertEqual(entries[1]["hooks"], [self.handler()])

            p = self.run_actx(["init", "--agent", "codex", "--uninstall"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(hooks_file, encoding="utf-8") as handle:
                data = json.load(handle)
            entries = data["hooks"]["PreToolUse"]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["matcher"], "Bash")
            self.assertEqual(len(entries[0]["hooks"]), 1)
            self.assertNotIn(self.handler(), entries[0]["hooks"])

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
            # TK-65: OpenCode v2 plugin form only (default {id, setup},
            # ctx.tool.hook("execute.before"), shell tool, actx hook).
            for needle in ("export default", 'id: "actx"', "setup(ctx)",
                           'ctx.tool.hook("execute.before"',
                           '"hook", "--agent", "opencode"', "execFileSync",
                           "input: JSON.stringify", 'event.tool !== "shell"',
                           "throw new Error", "catch"):
                self.assertIn(needle, content)
            for needle in ("tool.execute.before", "export const", '"rewrite"',
                           '"bash"'):
                self.assertNotIn(needle, content)

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

    def test_tier2_replaces_stale_section(self):
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, ".grok", "rules", "actx.md")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("Other rules\n\n" + _STALE_SECTION + "\n")
            p = self.run_actx(["init", "--agent", "grok"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(path, encoding="utf-8") as handle:
                content = handle.read()
            self.assertIn("Other rules", content)
            self.assertIn(INSTRUCTION_SECTION, content)
            self.assertNotIn("prefix read-only commands", content)
            self.assertEqual(content.count("## Output compression (actx)"), 1)
            p = self.run_actx(["init", "--agent", "grok"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(path, encoding="utf-8") as handle:
                again = handle.read()
            self.assertEqual(again, content)

    def test_tier2_package_discipline_present_and_deduped(self):
        # TK-51: the Tier-2 section carries the package-manager discipline;
        # double init keeps it exactly once (replace-in-place, TK-30 parity).
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, ".grok", "rules", "actx.md")
            for _ in range(2):
                p = self.run_actx(["init", "--agent", "grok"], home)
                self.assertEqual(p.returncode, 0, p.stderr)
            with open(path, encoding="utf-8") as handle:
                content = handle.read()
            self.assertEqual(content.count("## Output compression (actx)"), 1)
            self.assertEqual(content.count("Package manager discipline:"), 1)
            self.assertIn("require human confirmation (ask)", content)
            self.assertIn("npm ci", content)
            self.assertIn("frozen-lockfile", content)

            # A pre-TK-51 body (without the discipline) is replaced in place.
            os.remove(path)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(_STALE_SECTION + "\n")
            p = self.run_actx(["init", "--agent", "grok"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(path, encoding="utf-8") as handle:
                content = handle.read()
            self.assertEqual(content.count("## Output compression (actx)"), 1)
            self.assertIn("Package manager discipline:", content)

    def test_tier2_compact_flags_present_and_deduped(self):
        # TK-45: the Tier-2 section carries the compact-flags conventions;
        # double init keeps exactly one block (replace-in-place, TK-30 parity).
        with tempfile.TemporaryDirectory() as home:
            path = os.path.join(home, ".grok", "rules", "actx.md")
            for _ in range(2):
                p = self.run_actx(["init", "--agent", "grok"], home)
                self.assertEqual(p.returncode, 0, p.stderr)
            with open(path, encoding="utf-8") as handle:
                content = handle.read()
            self.assertEqual(content.count("## Output compression (actx)"), 1)
            self.assertEqual(content.count("Prefer compact flags"), 1)
            self.assertIn("git log -n 50", content)
            self.assertIn("kubectl get -o json", content)
            self.assertIn("LIMIT n", content)

            # A pre-TK-45 body (discipline, no compact-flags table) is
            # replaced in place (TK-51 precedent, test above).
            os.remove(path)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(_PRE_TK45_SECTION + "\n")
            p = self.run_actx(["init", "--agent", "grok"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(path, encoding="utf-8") as handle:
                content = handle.read()
            self.assertEqual(content.count("## Output compression (actx)"), 1)
            self.assertIn("Prefer compact flags", content)
            self.assertIn("Package manager discipline:", content)

    def test_raw_sentence_says_values_are_masked(self):
        # TK-61 review finding 8 (PRD 6.3 text): --raw masks secret values;
        # an installed section with the old sentence is replaced in place.
        new = (
            "For full output, run without `actx`; `actx --raw <command>` "
            "prints the raw output with secret values masked."
        )
        old = "For full output, run without `actx` or use `actx --raw <command>`."
        self.assertIn(new, INSTRUCTION_SECTION)
        self.assertNotIn(old, INSTRUCTION_SECTION)
        previous = INSTRUCTION_SECTION.replace(new, old)
        with tempfile.TemporaryDirectory() as home:
            rules = os.path.join(home, ".grok", "rules", "actx.md")
            os.makedirs(os.path.dirname(rules), exist_ok=True)
            with open(rules, "w", encoding="utf-8") as handle:
                handle.write("Other rules\n\n" + previous)
            p = self.run_actx(["init", "--agent", "grok"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(rules, encoding="utf-8") as handle:
                content = handle.read()
        self.assertEqual(content, "Other rules\n\n" + INSTRUCTION_SECTION + "\n")

    def test_tier2_section_matches_conventions_render(self):
        # REQ-01: the section renders from the single conventions source.
        from actx_lib import conventions

        self.assertIn(conventions.render_tier2(), INSTRUCTION_SECTION)

    def test_tier2_section_nonempty_with_header(self):
        # G2b: INSTRUCTION_SECTION is a non-empty string carrying the
        # section header (a broken render degrades, never empties it).
        self.assertTrue(INSTRUCTION_SECTION.strip())
        self.assertIn("## Output compression (actx)", INSTRUCTION_SECTION)

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
            self.assertFalse(os.path.exists(os.path.join(home, ".config", "devin")))
            self.assertFalse(os.path.exists(os.path.join(home, ".pi")))
            grok_rules = os.path.join(home, ".grok", "rules", "actx.md")
            with open(grok_rules, encoding="utf-8") as handle:
                self.assertIn(INSTRUCTION_SECTION, handle.read())

    def test_autodetect_devin_and_pi(self):
        # TK-65: devin is detected by its config dir, pi by its agent dir.
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, ".config", "devin"))
            os.makedirs(os.path.join(home, ".pi", "agent"))
            p = self.run_actx(["init"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue(os.path.exists(
                os.path.join(home, ".config", "devin", "config.json")))
            self.assertTrue(os.path.exists(
                os.path.join(home, ".pi", "agent", "extensions", "actx.ts")))
            self.assertFalse(os.path.exists(os.path.join(home, ".claude")))
            self.assertFalse(os.path.exists(
                os.path.join(home, ".config", "opencode")))

    def test_agent_all_installs_everything(self):
        with tempfile.TemporaryDirectory() as home:
            p = self.run_actx(["init", "--agent", "all"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            # No ~/.hermes in this HOME: the hermes gate skips before any
            # subprocess (CHK-05(1)), so the run stays rc 0 and offline.
            self.assertIn("hermes: no ~/.hermes data root - skipping", p.stderr)
            self.assertIn(INSTRUCTION_SECTION, p.stdout)

            for path in (
                os.path.join(home, ".claude", "settings.json"),
                os.path.join(home, ".codex", "hooks.json"),
                os.path.join(home, ".config", "opencode", "plugins", "actx.ts"),
                os.path.join(home, ".grok", "rules", "actx.md"),
                os.path.join(home, ".cline", "rules", "actx.md"),
                os.path.join(home, ".codeium", "windsurf", "memories", "global_rules.md"),
                os.path.join(home, ".gemini", "config", "hooks.json"),
                os.path.join(home, ".config", "devin", "config.json"),
                os.path.join(home, ".pi", "agent", "extensions", "actx.ts"),
                os.path.join(home, ".dsh", "actx", "actx-dsh.mjs"),
                os.path.join(home, ".dsh", "cordis.patch.yml"),
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
                "gemini",
                "devin",
                "pi",
                "dsh",
            ):
                self.assertIn("%s: installed" % agent, p.stdout)
            self.assertIn("hermes: not installed", p.stdout)
            self.assertIn("cursor: manual (cursor)", p.stdout)

    def test_gemini_double_init_single_entry_and_uninstall(self):
        with tempfile.TemporaryDirectory() as home:
            hooks_file = os.path.join(home, ".gemini", "config", "hooks.json")
            for _ in range(2):
                p = self.run_actx(["init", "--agent", "gemini"], home)
                self.assertEqual(p.returncode, 0, p.stderr)
            with open(hooks_file, encoding="utf-8") as handle:
                data = json.load(handle)
            entry = data["actx-gate"]["PreToolUse"][0]
            self.assertEqual(entry["matcher"], "run_command")
            self.assertEqual(len(entry["hooks"]), 1)
            self.assertEqual(entry["hooks"][0], self.handler())

            p = self.run_actx(["init", "--show"], home)
            self.assertIn("gemini: installed", p.stdout)

            p = self.run_actx(["init", "--agent", "gemini", "--uninstall"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(hooks_file, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertNotIn("actx-gate", data)

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
            hooks_file = os.path.join(home, ".gemini", "config", "hooks.json")
            os.makedirs(os.path.dirname(hooks_file), exist_ok=True)
            original = '{\n  "actx-gate": [broken\n}\n'
            with open(hooks_file, "w", encoding="utf-8") as handle:
                handle.write(original)
            p = self.run_actx(["init", "--agent", "gemini"], home)
            self.assertEqual(p.returncode, 1)
            with open(hooks_file, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), original)

    def test_unknown_agent_exit_1(self):
        with tempfile.TemporaryDirectory() as home:
            p = self.run_actx(["init", "--agent", "bogus"], home)
            self.assertEqual(p.returncode, 1)
            self.assertIn("unknown agent", p.stderr)

    def test_claude_init_replaces_stale_actx_hook(self):
        with tempfile.TemporaryDirectory() as home:
            settings = os.path.join(home, ".claude", "settings.json")
            os.makedirs(os.path.dirname(settings), exist_ok=True)
            stale = shlex.quote("/opt/homebrew/Cellar/actx/2.2/libexec/actx") + " hook"
            other = {"type": "command", "command": "echo existing", "timeout": 10}
            with open(settings, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "matcher": "Bash",
                                    "hooks": [
                                        {"type": "command", "command": stale, "timeout": 10},
                                        other,
                                    ],
                                }
                            ]
                        }
                    },
                    handle,
                )
            p = self.run_actx(["init", "--agent", "claude"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(settings, encoding="utf-8") as handle:
                data = json.load(handle)
            hooks = data["hooks"]["PreToolUse"][0]["hooks"]
            self.assertEqual(len(hooks), 2)
            self.assertIn(self.handler(), hooks)
            self.assertIn(other, hooks)
            self.assertNotIn(stale, [h.get("command") for h in hooks])

    def test_abs_path_keeps_absolute_arg0(self):
        from actx_lib import installer

        with mock.patch("sys.argv", ["/opt/homebrew/bin/actx"]):
            self.assertEqual(installer.abs_path(), "/opt/homebrew/bin/actx")

    def test_abs_path_relative_with_slash(self):
        from actx_lib import installer

        with mock.patch("sys.argv", ["bin/actx"]):
            self.assertEqual(installer.abs_path(), os.path.abspath("bin/actx"))

    def test_claude_uninstall_removes_stale_actx_hook(self):
        with tempfile.TemporaryDirectory() as home:
            settings = os.path.join(home, ".claude", "settings.json")
            os.makedirs(os.path.dirname(settings), exist_ok=True)
            stale = shlex.quote("/opt/homebrew/Cellar/actx/2.2/libexec/actx") + " hook"
            other = {"type": "command", "command": "echo existing", "timeout": 10}
            with open(settings, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "hooks": {
                            "PreToolUse": [
                                {
                                    "matcher": "Bash",
                                    "hooks": [
                                        {"type": "command", "command": stale, "timeout": 10},
                                        other,
                                    ],
                                }
                            ]
                        }
                    },
                    handle,
                )
            p = self.run_actx(["init", "--agent", "claude", "--uninstall"], home)
            self.assertEqual(p.returncode, 0, p.stderr)
            with open(settings, encoding="utf-8") as handle:
                data = json.load(handle)
            hooks = data["hooks"]["PreToolUse"][0]["hooks"]
            self.assertEqual(hooks, [other])


# TK-65 (plan D5 §4-§6): OpenCode XDG path, pi extension, Devin hook.
DEVIN_COMMAND = shlex.quote(ACTX) + " hook --agent devin"
DEVIN_HANDLER = {"type": "command", "command": DEVIN_COMMAND, "timeout": 10}
DEVIN_ENTRY = {"matcher": "^exec$", "hooks": [DEVIN_HANDLER]}
# Synthetic config with the owner's key set (devin-findings.md §6), no hooks.
DEVIN_OWNER_SHAPED = {
    "version": 1,
    "devin": {"org_id": "org-test"},
    "shell": {"setup_complete": True},
    "theme_mode": "dark",
    "agent": {"model": "test-model"},
    "permissions": {"allow": ["Exec(ls)", "Read(**)"]},
    "read_config_from": {"claude": False},
}
USER_BASH_ENTRY = {"matcher": "Bash",
                   "hooks": [{"type": "command", "command": "echo bash-user"}]}
USER_EXEC_HANDLER = {"type": "command", "command": "echo exec-user", "timeout": 5}
# TK-72: the one patch item actx writes into ~/.dsh/cordis.patch.yml (JSON,
# which dsh reads as YAML).  The home patch is a list of patch OPERATIONS: a
# new entry goes in through `insert`, while a bare `{"id": ...}` item would
# override an existing entry (and be dropped when none matches).
DSH_PATCH_ITEM = {"insert": [{"id": "actx", "name": "./actx/actx-dsh.mjs"}]}
# The shape written by the first build of this adapter (dsh dropped it as an
# unmatched override); recognition must still clean it up.
DSH_LEGACY_ROW = {"id": "actx", "name": "./actx/actx-dsh.mjs"}

# TK-69/CHK-05: the exact command string and the two records it keys - the
# hook entry in `hooks.pre_tool_call` and the approval in the profile's
# shell-hooks-allowlist.json.  The default profile takes no `-p` flag.
HERMES_DEFAULT_PROFILE = "default-profile"
HERMES_COMMAND = shlex.quote(ACTX) + " hook --agent hermes"
HERMES_ENTRY = {
    "command": HERMES_COMMAND,
    "matcher": "^terminal$",
    "timeout": 10,
    "fail_closed": True,
}
HERMES_APPROVAL = {"event": "pre_tool_call", "command": HERMES_COMMAND}


class HermesCli:
    """In-process stand-in for the `hermes` binary: the only subprocess the
    hermes suite allows.  It keeps per-profile hooks state, so a `config set`
    answers the next `config get` and re-init is genuinely idempotent."""

    def __init__(self, home):
        self.home = home
        self.calls = []
        self.hooks = {}
        self.raw_hooks = {}
        self.paths = {}
        self.set_rc = {}
        self.spawn_errors = {}

    def profile_and_rest(self, argv):
        rest = list(argv[1:])
        if rest[:1] == ["-p"]:
            return rest[1], rest[2:]
        return HERMES_DEFAULT_PROFILE, rest

    def __call__(self, argv, capture_output=True, text=True, timeout=None):
        self.calls.append(list(argv))
        profile, rest = self.profile_and_rest(argv)
        if profile in self.spawn_errors:
            raise self.spawn_errors[profile]
        if rest == ["config", "get", "hooks", "--json"]:
            payload = self.raw_hooks.get(
                profile, json.dumps(self.hooks.get(profile, {})))
            return subprocess.CompletedProcess(argv, 0, payload, "")
        if rest == ["config", "path"]:
            path = self.paths.get(
                profile, os.path.join(self.home, ".hermes", "config.yaml"))
            return subprocess.CompletedProcess(argv, 0, path + "\n", "")
        if rest[:2] == ["config", "set"] and len(rest) == 4:
            key, payload = rest[2], rest[3]
            code = self.set_rc.get(profile, 0)
            if code != 0:
                return subprocess.CompletedProcess(argv, code, "", "")
            if key == "hooks":
                # The live shape (CHK-08): a section is not a scalar.
                return subprocess.CompletedProcess(
                    argv, 1, "",
                    "cannot set 'hooks' to a scalar - 'hooks' is a "
                    "configuration section with 1 sub-key(s).")
            if not key.startswith("hooks."):
                raise AssertionError("unexpected hermes argv: %r" % (argv,))
            self.hooks.setdefault(profile, {})[key[len("hooks."):]] = \
                json.loads(payload)
            return subprocess.CompletedProcess(argv, 0, "", "")
        if rest[:2] == ["config", "unset"] and len(rest) == 3:
            path = rest[2]
            if path == "hooks":
                self.hooks[profile] = {}
            elif path.startswith("hooks."):
                self.hooks.setdefault(profile, {}).pop(path[len("hooks."):],
                                                       None)
            else:
                raise AssertionError("unexpected hermes argv: %r" % (argv,))
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError("unexpected hermes argv: %r" % (argv,))

    def verb_calls(self, verb, profile=None):
        found = []
        for argv in self.calls:
            name, rest = self.profile_and_rest(argv)
            if (rest[:2] == ["config", verb]
                    and (profile is None or name == profile)):
                found.append(argv)
        return found

    def set_calls(self, profile=None):
        return self.verb_calls("set", profile)

    def unset_calls(self, profile=None):
        return self.verb_calls("unset", profile)


class AdapterInitTests(unittest.TestCase):
    def run_actx(self, args, home, extra_env=None):
        return subprocess.run(
            [ACTX] + args,
            capture_output=True,
            text=True,
            env=isolated_env(home, extra_env),
        )

    def init(self, home, *args, extra_env=None):
        p = self.run_actx(["init"] + list(args), home, extra_env)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p

    @staticmethod
    def substituted_actx(content):
        match = re.search(r"const ACTX = (.*)", content)
        value = match.group(1).strip().rstrip(";")
        return json.loads(value)

    # --- OpenCode -------------------------------------------------------
    def test_opencode_honours_xdg_config_home(self):
        with tempfile.TemporaryDirectory() as home:
            xdg = os.path.join(home, "xdg")
            env = {"XDG_CONFIG_HOME": xdg}
            self.init(home, "--agent", "opencode", extra_env=env)
            plugin = os.path.join(xdg, "opencode", "plugins", "actx.ts")
            self.assertTrue(os.path.exists(plugin))
            self.assertFalse(os.path.exists(os.path.join(home, ".config")))
            p = self.init(home, "--show", extra_env=env)
            self.assertIn("opencode: installed", p.stdout)
            self.init(home, "--agent", "opencode", "--uninstall", extra_env=env)
            self.assertFalse(os.path.exists(plugin))

    # --- pi ---------------------------------------------------------------
    def check_pi_extension(self, path):
        with open(path, encoding="utf-8") as handle:
            content = handle.read()
        self.assertNotIn("__ACTX_ABS_PATH__", content)
        for needle in ("export default function", 'pi.on("tool_call"',
                       'toolName !== "bash"', '"hook", "--agent", "pi"',
                       "await runActx(", 'on("close"', "child.kill()", "3000",
                       "block: true", "catch"):
            self.assertIn(needle, content)
        for needle in ("execFileSync", "throw ", "ctx.ui.confirm"):
            self.assertNotIn(needle, content)
        self.assertEqual(os.path.realpath(self.substituted_actx(content)), ACTX)

    def test_pi_install_show_uninstall_default_dir(self):
        with tempfile.TemporaryDirectory() as home:
            for _ in range(2):
                self.init(home, "--agent", "pi")
            ext_dir = os.path.join(home, ".pi", "agent", "extensions")
            self.assertEqual(os.listdir(ext_dir), ["actx.ts"])
            self.check_pi_extension(os.path.join(ext_dir, "actx.ts"))
            self.assertIn("pi: installed", self.init(home, "--show").stdout)
            self.init(home, "--agent", "pi", "--uninstall")
            self.assertEqual(os.listdir(ext_dir), [])
            self.assertIn("pi: not installed", self.init(home, "--show").stdout)

    def test_pi_honours_pi_coding_agent_dir(self):
        with tempfile.TemporaryDirectory() as home:
            agent_dir = os.path.join(home, "pi-agent")
            env = {"PI_CODING_AGENT_DIR": agent_dir}
            self.init(home, "--agent", "pi", extra_env=env)
            path = os.path.join(agent_dir, "extensions", "actx.ts")
            self.check_pi_extension(path)
            self.assertFalse(os.path.exists(os.path.join(home, ".pi")))
            self.init(home, "--agent", "pi", "--uninstall", extra_env=env)
            self.assertFalse(os.path.exists(path))

    # --- Devin ------------------------------------------------------------
    def devin_path(self, home):
        return os.path.join(home, ".config", "devin", "config.json")

    def write_devin(self, home, text, mode=0o600):
        path = self.devin_path(home)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(path, mode)
        return path

    def load(self, path):
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)

    def test_devin_missing_file_created_0600(self):
        with tempfile.TemporaryDirectory() as home:
            self.init(home, "--agent", "devin")
            path = self.devin_path(home)
            self.assertEqual(self.load(path), {"hooks": {"PreToolUse": [DEVIN_ENTRY]}})
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertIn("devin: installed", self.init(home, "--show").stdout)

    def test_devin_empty_config(self):
        with tempfile.TemporaryDirectory() as home:
            path = self.write_devin(home, "{}\n")
            self.init(home, "--agent", "devin")
            self.assertEqual(self.load(path), {"hooks": {"PreToolUse": [DEVIN_ENTRY]}})
            self.init(home, "--agent", "devin", "--uninstall")
            self.assertEqual(self.load(path), {})

    def test_devin_owner_shaped_config_round_trip_keeps_0600(self):
        with tempfile.TemporaryDirectory() as home:
            path = self.write_devin(home, json.dumps(DEVIN_OWNER_SHAPED, indent=2))
            for _ in range(2):
                self.init(home, "--agent", "devin")
            data = self.load(path)
            self.assertEqual(data.pop("hooks"), {"PreToolUse": [DEVIN_ENTRY]})
            self.assertEqual(data, DEVIN_OWNER_SHAPED)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.init(home, "--agent", "devin", "--uninstall")
            self.assertEqual(self.load(path), DEVIN_OWNER_SHAPED)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_devin_user_hooks_untouched_ours_appended(self):
        original = {
            "theme_mode": "dark",
            "hooks": {
                "PreToolUse": [
                    USER_BASH_ENTRY,
                    {"matcher": "^exec$", "hooks": [USER_EXEC_HANDLER]},
                ],
                "PostToolUse": [USER_BASH_ENTRY],
            },
        }
        with tempfile.TemporaryDirectory() as home:
            path = self.write_devin(home, json.dumps(original))
            for _ in range(2):
                self.init(home, "--agent", "devin")
            data = self.load(path)
            self.assertEqual(data["hooks"]["PreToolUse"], [
                USER_BASH_ENTRY,
                {"matcher": "^exec$", "hooks": [USER_EXEC_HANDLER, DEVIN_HANDLER]},
            ])
            self.assertEqual(data["hooks"]["PostToolUse"], [USER_BASH_ENTRY])
            self.init(home, "--agent", "devin", "--uninstall")
            self.assertEqual(self.load(path), original)

    def test_devin_double_init_one_handler_file_unchanged(self):
        with tempfile.TemporaryDirectory() as home:
            self.init(home, "--agent", "devin")
            path = self.devin_path(home)
            with open(path, "rb") as handle:
                first = handle.read()
            os.utime(path, (1, 1))
            self.init(home, "--agent", "devin")
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), first)
            self.assertEqual(os.stat(path).st_mtime, 1)  # not rewritten
            entries = self.load(path)["hooks"]["PreToolUse"]
            self.assertEqual(entries, [DEVIN_ENTRY])

    def test_devin_stale_actx_handlers_replaced(self):
        stale_plain = {"type": "command", "timeout": 10,
                       "command": "'/opt/homebrew/Cellar/actx/2.2/libexec/actx' hook"}
        stale_agent = {"type": "command", "timeout": 10,
                       "command": "/old/bin/actx hook --agent devin"}
        original = {"hooks": {"PreToolUse": [
            {"matcher": "", "hooks": [stale_plain]},
            {"matcher": "^exec$", "hooks": [USER_EXEC_HANDLER, stale_agent]},
        ]}}
        with tempfile.TemporaryDirectory() as home:
            path = self.write_devin(home, json.dumps(original))
            self.init(home, "--agent", "devin")
            self.assertEqual(self.load(path), {"hooks": {"PreToolUse": [
                {"matcher": "^exec$", "hooks": [USER_EXEC_HANDLER, DEVIN_HANDLER]},
            ]}})

    def test_devin_refuses_malformed_shapes_byte_identical(self):
        cases = {
            "comment": '{\n  // comment\n  "theme_mode": "dark"\n}\n',
            "top_level_list": "[]\n",
            "hooks_not_dict": '{"hooks": []}\n',
            "hooks_null": '{"hooks": null}\n',
            "pretool_not_list": '{"hooks": {"PreToolUse": {}}}\n',
            "entry_not_dict": '{"hooks": {"PreToolUse": ["x"]}}\n',
            "entry_hooks_not_list": (
                '{"hooks": {"PreToolUse": [{"matcher": "^exec$", "hooks": "x"}]}}\n'),
        }
        for name, text in cases.items():
            for args in (["--agent", "devin"], ["--agent", "devin", "--uninstall"]):
                with self.subTest(case=name, args=args):
                    with tempfile.TemporaryDirectory() as home:
                        path = self.write_devin(home, text)
                        p = self.run_actx(["init"] + args, home)
                        self.assertEqual(p.returncode, 1, p.stdout)
                        self.assertIn(path, p.stderr)
                        if "--uninstall" not in args:
                            self.assertIn('"^exec$"', p.stderr)
                            self.assertIn("hook --agent devin", p.stderr)
                        with open(path, encoding="utf-8") as handle:
                            self.assertEqual(handle.read(), text)

    def test_devin_honours_xdg_config_home(self):
        with tempfile.TemporaryDirectory() as home:
            xdg = os.path.join(home, "xdg")
            env = {"XDG_CONFIG_HOME": xdg}
            self.init(home, "--agent", "devin", extra_env=env)
            path = os.path.join(xdg, "devin", "config.json")
            self.assertEqual(self.load(path), {"hooks": {"PreToolUse": [DEVIN_ENTRY]}})
            self.assertFalse(os.path.exists(os.path.join(home, ".config")))
            self.assertIn("devin: installed",
                          self.init(home, "--show", extra_env=env).stdout)

    # --- dsh --------------------------------------------------------------
    def dsh_paths(self, home):
        return (
            os.path.join(home, ".dsh", "actx", "actx-dsh.mjs"),
            os.path.join(home, ".dsh", "cordis.patch.yml"),
        )

    def write_dsh_patch(self, home, text):
        _, patch = self.dsh_paths(home)
        os.makedirs(os.path.dirname(patch), exist_ok=True)
        with open(patch, "w", encoding="utf-8") as handle:
            handle.write(text)
        return patch

    def test_dsh_install_writes_mjs_and_patch(self):
        with tempfile.TemporaryDirectory() as home:
            self.init(home, "--agent", "dsh")
            mjs, patch = self.dsh_paths(home)
            with open(patch, encoding="utf-8") as handle:
                self.assertEqual(handle.read(),
                                 json.dumps([DSH_PATCH_ITEM], indent=2) + "\n")
            with open(mjs, encoding="utf-8") as handle:
                content = handle.read()
            self.assertNotIn("__ACTX_ABS_PATH__", content)
            # CHK-03: the transport contract, and the negative needle proving
            # no rewrite verdict is ever read or applied (dsh freezes input).
            for needle in ("export default", "tools/pre-execute",
                           "prepend: true", '"hook", "--agent", "dsh"',
                           "bash", "pwsh", "deny", "ask", "next()", "catch",
                           "3000", "detached: true",
                           "process.kill(-child.pid", 'child.kill("SIGKILL")'):
                self.assertIn(needle, content)
            self.assertNotIn("updatedInput", content)
            self.assertEqual(os.path.realpath(self.substituted_actx(content)), ACTX)
            self.assertIn("dsh: installed", self.init(home, "--show").stdout)

    def test_dsh_double_init_patch_unchanged(self):
        with tempfile.TemporaryDirectory() as home:
            self.init(home, "--agent", "dsh")
            _, patch = self.dsh_paths(home)
            with open(patch, "rb") as handle:
                first = handle.read()
            os.utime(patch, (1, 1))
            self.init(home, "--agent", "dsh")
            with open(patch, "rb") as handle:
                self.assertEqual(handle.read(), first)
            self.assertEqual(os.stat(patch).st_mtime, 1)  # not rewritten
            self.assertEqual(self.load(patch), [DSH_PATCH_ITEM])

    def test_dsh_stale_ours_replaced(self):
        # Every shape that resolves to our mjs is ours: the legacy plain entry
        # (absolute, bare-relative, file:// URL) and a non-canonical insert
        # operation.  One canonical insert operation replaces them all.
        with tempfile.TemporaryDirectory() as home:
            mjs, patch = self.dsh_paths(home)
            stale = [
                {"id": "actx", "name": mjs},
                {"id": "actx", "name": "actx/actx-dsh.mjs"},
                {"id": "actx", "name": "file://" + mjs},
                {"insert": [{"id": "actx", "name": mjs}]},
            ]
            self.write_dsh_patch(home, json.dumps(stale, indent=2))
            self.init(home, "--agent", "dsh")
            self.assertEqual(self.load(patch), [DSH_PATCH_ITEM])

    def test_dsh_foreign_patch_items_untouched(self):
        # The home patch is a list of patch operations.  Nothing here is ours:
        # another plugin (plain entry and insert), an insert that also holds our
        # entry among others, and override items carrying our id with a foreign
        # or missing name.
        foreign = [
            {"id": "other", "name": "./other/x.mjs"},
            {"insert": [{"id": "other", "name": "./other/y.mjs"}]},
            {"insert": [DSH_LEGACY_ROW,
                        {"id": "other", "name": "./other/z.mjs"}]},
            {"id": "actx", "name": "https://example.com/x.mjs"},
            {"id": "actx"},
        ]
        with tempfile.TemporaryDirectory() as home:
            mjs, patch = self.dsh_paths(home)
            self.write_dsh_patch(home, json.dumps(foreign, indent=2))
            self.init(home, "--agent", "dsh")
            self.assertEqual(self.load(patch), foreign + [DSH_PATCH_ITEM])
            self.init(home, "--agent", "dsh", "--uninstall")
            self.assertFalse(os.path.exists(mjs))
            self.assertEqual(self.load(patch), foreign)

    def test_dsh_legacy_plain_row_recognised_and_cleaned(self):
        # A plain entry is what the first build wrote; dsh read it as an
        # override that matched nothing.  It counts as installed, a re-init
        # replaces it, and an uninstall removes it.
        with tempfile.TemporaryDirectory() as home:
            self.init(home, "--agent", "dsh")
            mjs, patch = self.dsh_paths(home)
            self.write_dsh_patch(home, json.dumps([DSH_LEGACY_ROW], indent=2))
            self.assertIn("dsh: installed", self.init(home, "--show").stdout)
            self.init(home, "--agent", "dsh")
            self.assertEqual(self.load(patch), [DSH_PATCH_ITEM])
            self.write_dsh_patch(home, json.dumps([DSH_LEGACY_ROW], indent=2))
            self.init(home, "--agent", "dsh", "--uninstall")
            self.assertFalse(os.path.exists(mjs))
            self.assertFalse(os.path.exists(patch))

    def test_dsh_row_predicate_forms(self):
        from actx_lib import installer

        with tempfile.TemporaryDirectory() as root:
            patch = os.path.join(root, "cordis.patch.yml")
            mjs = os.path.join(root, "actx", "actx-dsh.mjs")
            for name, expected in (
                ("./actx/actx-dsh.mjs", True),
                ("actx/actx-dsh.mjs", True),
                (mjs, True),
                ("file://" + mjs, True),
                ("https://example.com/x.mjs", False),
                ("./actx/other.mjs", False),
                ("/old/bin/actx-dsh.mjs", False),
                (None, False),
            ):
                with self.subTest(form="legacy", name=name):
                    self.assertIs(installer._dsh_row_is_ours(
                        {"id": "actx", "name": name}, patch, mjs), expected)
                with self.subTest(form="insert", name=name):
                    self.assertIs(installer._dsh_row_is_ours(
                        {"insert": [{"id": "actx", "name": name}]}, patch, mjs),
                        expected)
            for row, expected in (
                ({"insert": []}, False),
                ({"insert": "x"}, False),
                ({"insert": [{"id": "actx", "name": mjs},
                             {"id": "other", "name": "./other/x.mjs"}]}, False),
                ({"insert": [{"id": "other", "name": mjs}]}, False),
                ({"id": "other", "name": mjs}, False),
                ({"id": "actx"}, False),
                ("row", False),
            ):
                with self.subTest(row=row):
                    self.assertIs(installer._dsh_row_is_ours(row, patch, mjs),
                                  expected)

    def test_dsh_refuses_hand_written_yaml_byte_identical(self):
        original = "- id: my-own\n  name: ./mine.mjs\n"
        with tempfile.TemporaryDirectory() as home:
            patch = self.write_dsh_patch(home, original)
            for args, verb in (
                (["--agent", "dsh"], "cannot install"),
                (["--agent", "dsh", "--uninstall"], "cannot uninstall"),
            ):
                with self.subTest(args=args):
                    p = self.run_actx(["init"] + args, home)
                    self.assertEqual(p.returncode, 1, p.stdout)
                    self.assertIn(verb, p.stderr)
                    self.assertIn(patch, p.stderr)
                    self.assertIn("./actx/actx-dsh.mjs", p.stderr)
                    with open(patch, encoding="utf-8") as handle:
                        self.assertEqual(handle.read(), original)
            # A malformed patch reads as not installed, never as a traceback.
            self.assertIn("dsh: not installed", self.init(home, "--show").stdout)

    def test_dsh_uninstall_removes_both_files(self):
        with tempfile.TemporaryDirectory() as home:
            self.init(home, "--agent", "dsh")
            mjs, patch = self.dsh_paths(home)
            self.init(home, "--agent", "dsh", "--uninstall")
            self.assertFalse(os.path.exists(mjs))
            self.assertFalse(os.path.exists(patch))
            self.assertIn("dsh: not installed", self.init(home, "--show").stdout)

    def test_dsh_uninstall_with_nothing_installed_is_a_noop(self):
        with tempfile.TemporaryDirectory() as home:
            self.init(home, "--agent", "dsh", "--uninstall")
            self.assertEqual(os.listdir(home), [])

    def test_dsh_show_dir_alone_is_not_installed(self):
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, ".dsh"))
            self.assertIn("dsh: not installed", self.init(home, "--show").stdout)

    def test_dsh_autodetected_by_home_dir(self):
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, ".dsh"))
            self.init(home)
            mjs, patch = self.dsh_paths(home)
            self.assertTrue(os.path.exists(mjs))
            self.assertEqual(self.load(patch), [DSH_PATCH_ITEM])

    # --- shared -----------------------------------------------------------
    def test_is_actx_hook_command_exact_forms(self):
        from actx_lib import installer

        for command, expected in (
            ("actx hook", True),
            ("/opt/homebrew/bin/actx hook", True),
            ("'/Users/x/My Tools/actx' hook", True),
            ("/opt/homebrew/bin/actx hook --agent devin", True),
            ("'/a b/actx' hook --agent opencode", True),
            ("my-actx hook", False),
            ("actx hook && rm x", False),
            ("echo actx hook", False),
            ("actx hook --agent", False),
            ("actx hook --agent devin extra", False),
            ("actx hook --payload x", False),
            ("actx rewrite", False),
            ("'/a b/actx hook", False),
            (None, False),
        ):
            with self.subTest(command=command):
                self.assertIs(installer._is_actx_hook_command(command), expected)

    def test_claude_keeps_user_hook_that_only_looks_like_actx(self):
        with tempfile.TemporaryDirectory() as home:
            settings = os.path.join(home, ".claude", "settings.json")
            os.makedirs(os.path.dirname(settings))
            user = [{"type": "command", "command": c}
                    for c in ("my-actx hook", "actx hook && rm x", "echo actx hook")]
            with open(settings, "w", encoding="utf-8") as handle:
                json.dump({"hooks": {"PreToolUse": [
                    {"matcher": "Bash", "hooks": list(user)}]}}, handle)
            self.init(home, "--agent", "claude")
            self.init(home, "--agent", "claude", "--uninstall")
            self.assertEqual(self.load(settings)["hooks"]["PreToolUse"][0]["hooks"], user)

    def test_help_lists_new_agents(self):
        with tempfile.TemporaryDirectory() as home:
            p = self.init(home, "--help")
            self.assertRegex(p.stdout, r"\bdevin\b")
            self.assertRegex(p.stdout, r"\bpi\b")
            self.assertRegex(p.stdout, r"\bdsh\b")
            self.assertRegex(p.stdout, r"\bhermes\b")


class HermesInstallerTests(unittest.TestCase):
    """CHK-05: the hermes installer against a mocked CLI.  Every case patches
    `subprocess.run` and `_hermes_binary`, so the result is the same on a
    machine without Hermes and on the owner's machine; `HOME` is a temp dir."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = tmp.name
        self.root = os.path.join(self.home, ".hermes")
        self.allowlist = os.path.join(self.root, "shell-hooks-allowlist.json")
        self.cli = HermesCli(self.home)
        # XDG_CONFIG_HOME / PI_CODING_AGENT_DIR are blanked so a caller's
        # overrides cannot point auto-detection at a real agent directory.
        env = {"HOME": self.home, "XDG_CONFIG_HOME": "",
               "PI_CODING_AGENT_DIR": ""}
        for patcher in (
            mock.patch.dict(os.environ, env),
            mock.patch("actx_lib.installer._hermes_binary",
                       return_value="/fake/hermes"),
            mock.patch("actx_lib.installer.abs_path", return_value=ACTX),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        run_patch = mock.patch(
            "actx_lib.installer.subprocess.run", side_effect=self.cli)
        self.run_mock = run_patch.start()
        self.addCleanup(run_patch.stop)

    # --- helpers ----------------------------------------------------------
    def make_root(self):
        os.makedirs(self.root, exist_ok=True)

    def write_json(self, path, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(data, indent=2) + "\n")

    def load(self, path):
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)

    def write_config(self, data):
        path = os.path.join(self.home, ".config", "actx", "config.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        return path

    def run_installer(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            rc = installer.main(list(args))
        return rc, out.getvalue(), err.getvalue()

    # --- CHK-05 (1): the hermeticity gate --------------------------------
    def test_absent_data_root_skips_before_any_subprocess(self):
        rc, _, err = self.run_installer("--agent", "hermes")
        self.assertEqual(rc, 0)
        self.assertIn(
            "actx init: hermes: no ~/.hermes data root - skipping "
            "(run hermes once first)", err)
        self.assertEqual(self.run_mock.call_count, 0)
        self.assertFalse(os.path.exists(self.allowlist))
        self.assertFalse(os.path.exists(os.path.join(self.home, ".config", "actx")))
        rc, _, err = self.run_installer("--agent", "hermes", "--uninstall")
        self.assertEqual(rc, 0)
        self.assertIn("no ~/.hermes data root", err)
        self.assertEqual(self.run_mock.call_count, 0)

    def test_missing_binary_skips_with_zero_subprocess(self):
        self.make_root()
        with mock.patch("actx_lib.installer._hermes_binary", return_value=None):
            rc, _, err = self.run_installer("--agent", "hermes")
        self.assertEqual(rc, 0)
        self.assertIn("the hermes binary was not found on PATH - skipping", err)
        self.assertEqual(self.run_mock.call_count, 0)
        self.assertFalse(os.path.exists(self.allowlist))

    # --- CHK-05 (2): fresh profile, exact argv and payload ---------------
    def test_fresh_profile_writes_hook_and_allowlist(self):
        self.make_root()
        foreign = {"command": "echo foreign", "matcher": "^terminal$"}
        self.cli.hooks[HERMES_DEFAULT_PROFILE] = {
            "pre_tool_call": [foreign], "model": "test-model"}
        rc, _, err = self.run_installer("--agent", "hermes")
        self.assertEqual(rc, 0, err)
        expected_entries = [foreign, HERMES_ENTRY]
        self.assertEqual(self.cli.set_calls(), [[
            "/fake/hermes", "config", "set", "hooks.pre_tool_call",
            json.dumps(expected_entries, separators=(",", ":")),
        ]])
        self.assertEqual(self.cli.hooks[HERMES_DEFAULT_PROFILE], {
            "pre_tool_call": expected_entries, "model": "test-model"})
        self.assertIn(["/fake/hermes", "config", "get", "hooks", "--json"],
                      self.cli.calls)
        self.assertIn(["/fake/hermes", "config", "path"], self.cli.calls)
        with open(self.allowlist, encoding="utf-8") as handle:
            text = handle.read()
        self.assertEqual(text, json.dumps(
            {"approvals": [HERMES_APPROVAL]}, indent=2) + "\n")
        self.assertEqual(os.stat(self.allowlist).st_mode & 0o777, 0o600)

    # --- CHK-05 (3): foreign entries survive ------------------------------
    def test_foreign_entries_survive_a_reinit(self):
        self.make_root()
        foreign_hook = {"command": "/usr/local/bin/auditor hook",
                        "matcher": "^terminal$"}
        foreign_approval = {"event": "post_tool_call", "command": "echo done"}
        self.cli.hooks[HERMES_DEFAULT_PROFILE] = {
            "pre_tool_call": [foreign_hook]}
        self.write_json(self.allowlist,
                        {"approvals": [foreign_approval], "version": 2})
        for _ in range(2):
            rc, _, err = self.run_installer("--agent", "hermes")
            self.assertEqual(rc, 0, err)
        self.assertEqual(
            self.cli.hooks[HERMES_DEFAULT_PROFILE]["pre_tool_call"],
            [foreign_hook, HERMES_ENTRY])
        self.assertEqual(self.load(self.allowlist), {
            "approvals": [foreign_approval, HERMES_APPROVAL], "version": 2})

    # --- CHK-05 (4): a stale actx path is replaced in both files ----------
    def test_stale_actx_path_replaced_in_both_files(self):
        self.make_root()
        stale_command = shlex.quote("/old/bin/actx") + " hook --agent hermes"
        self.cli.hooks[HERMES_DEFAULT_PROFILE] = {"pre_tool_call": [
            {"command": stale_command, "matcher": "^terminal$", "timeout": 10}]}
        self.write_json(self.allowlist, {"approvals": [
            {"event": "pre_tool_call", "command": stale_command}]})
        rc, _, err = self.run_installer("--agent", "hermes")
        self.assertEqual(rc, 0, err)
        self.assertEqual(
            self.cli.hooks[HERMES_DEFAULT_PROFILE]["pre_tool_call"],
            [HERMES_ENTRY])
        self.assertEqual(self.load(self.allowlist)["approvals"],
                         [HERMES_APPROVAL])
        self.assertNotIn("/old/bin/actx", json.dumps(self.cli.hooks))

    # --- CHK-05 (5): double init is a no-op -------------------------------
    def test_double_init_does_not_write_again(self):
        self.make_root()
        self.assertEqual(self.run_installer("--agent", "hermes")[0], 0)
        with open(self.allowlist, "rb") as handle:
            first = handle.read()
        os.utime(self.allowlist, (1, 1))
        sets = len(self.cli.set_calls())
        rc, _, err = self.run_installer("--agent", "hermes")
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self.cli.set_calls()), sets)
        with open(self.allowlist, "rb") as handle:
            self.assertEqual(handle.read(), first)
        self.assertEqual(os.stat(self.allowlist).st_mtime, 1)

    # --- CHK-05 (6): uninstall reverses both sides ------------------------
    def test_uninstall_reverses_both_sides_including_stale(self):
        self.make_root()
        self.assertEqual(self.run_installer("--agent", "hermes")[0], 0)
        data = self.load(self.allowlist)
        data["approvals"].append({
            "event": "pre_tool_call",
            "command": "/old/bin/actx hook --agent hermes"})
        self.write_json(self.allowlist, data)
        rc, _, err = self.run_installer("--agent", "hermes", "--uninstall")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.cli.hooks[HERMES_DEFAULT_PROFILE], {})
        self.assertFalse(os.path.exists(self.allowlist))  # emptied -> deleted
        sets, unsets = len(self.cli.set_calls()), len(self.cli.unset_calls())
        rc, _, err = self.run_installer("--agent", "hermes", "--uninstall")
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self.cli.set_calls()), sets)  # nothing ours
        self.assertEqual(len(self.cli.unset_calls()), unsets)

    def test_uninstall_keeps_foreign_approvals(self):
        self.make_root()
        foreign = {"event": "post_tool_call", "command": "echo done"}
        self.write_json(self.allowlist,
                        {"approvals": [HERMES_APPROVAL, foreign], "version": 2})
        self.cli.hooks[HERMES_DEFAULT_PROFILE] = {
            "pre_tool_call": [HERMES_ENTRY]}
        rc, _, err = self.run_installer("--agent", "hermes", "--uninstall")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.load(self.allowlist),
                         {"approvals": [foreign], "version": 2})

    # --- CHK-08: the uninstall write path the live CLI accepts ------------
    def test_uninstall_empty_remainder_unsets_the_whole_section(self):
        self.make_root()
        self.assertEqual(self.run_installer("--agent", "hermes")[0], 0)
        self.cli.calls.clear()
        rc, _, err = self.run_installer("--agent", "hermes", "--uninstall")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.cli.unset_calls(),
                         [["/fake/hermes", "config", "unset", "hooks"]])
        self.assertEqual(self.cli.set_calls(), [])
        self.assertEqual(self.cli.hooks[HERMES_DEFAULT_PROFILE], {})

    def test_uninstall_with_foreign_sub_key_unsets_only_our_list(self):
        self.make_root()
        foreign = {"command": "echo after", "matcher": "^terminal$"}
        self.cli.hooks[HERMES_DEFAULT_PROFILE] = {
            "pre_tool_call": [HERMES_ENTRY], "post_tool_call": [foreign]}
        self.write_json(self.allowlist, {"approvals": [HERMES_APPROVAL]})
        rc, _, err = self.run_installer("--agent", "hermes", "--uninstall")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.cli.unset_calls(), [[
            "/fake/hermes", "config", "unset", "hooks.pre_tool_call"]])
        self.assertEqual(self.cli.set_calls(), [])
        self.assertEqual(self.cli.hooks[HERMES_DEFAULT_PROFILE],
                         {"post_tool_call": [foreign]})
        self.assertNotIn("post_tool_call", json.dumps(self.cli.calls))

    def test_uninstall_keeps_foreign_pre_tool_call_entries(self):
        self.make_root()
        foreign = {"command": "echo foreign", "matcher": "^terminal$"}
        self.cli.hooks[HERMES_DEFAULT_PROFILE] = {
            "pre_tool_call": [foreign, HERMES_ENTRY]}
        self.write_json(self.allowlist, {"approvals": [HERMES_APPROVAL]})
        rc, _, err = self.run_installer("--agent", "hermes", "--uninstall")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.cli.set_calls(), [[
            "/fake/hermes", "config", "set", "hooks.pre_tool_call",
            json.dumps([foreign], separators=(",", ":")),
        ]])
        self.assertEqual(self.cli.hooks[HERMES_DEFAULT_PROFILE],
                         {"pre_tool_call": [foreign]})

    # --- CHK-08: install writes only the changed sub-key ------------------
    def test_install_writes_only_the_changed_sub_key(self):
        self.make_root()
        foreign = {"command": "echo after", "matcher": "^terminal$"}
        self.cli.hooks[HERMES_DEFAULT_PROFILE] = {
            "pre_tool_call": [], "post_tool_call": [foreign]}
        rc, _, err = self.run_installer("--agent", "hermes")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.cli.set_calls(), [[
            "/fake/hermes", "config", "set", "hooks.pre_tool_call",
            json.dumps([HERMES_ENTRY], separators=(",", ":")),
        ]])
        self.assertEqual(self.cli.hooks[HERMES_DEFAULT_PROFILE],
                         {"pre_tool_call": [HERMES_ENTRY],
                          "post_tool_call": [foreign]})
        self.assertNotIn("post_tool_call", json.dumps(self.cli.set_calls()))

    def test_live_uninstall_shape_succeeds_end_to_end(self):
        """The shape that failed live (CHK-08): our entry is the only hook,
        so the emptied remainder is unset, never written whole."""
        self.make_root()
        rc, _, err = self.run_installer("--agent", "hermes")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.cli.hooks[HERMES_DEFAULT_PROFILE],
                         {"pre_tool_call": [HERMES_ENTRY]})
        rc, _, err = self.run_installer("--agent", "hermes", "--uninstall")
        self.assertEqual(rc, 0, err)
        self.assertEqual(err, "")
        self.assertEqual(self.cli.hooks[HERMES_DEFAULT_PROFILE], {})
        self.assertFalse(os.path.exists(self.allowlist))

    # --- CHK-05 (7): configured profiles ----------------------------------
    def test_configured_profiles_are_each_processed(self):
        self.make_root()
        self.write_config({"hermes_profiles": ["a", "b"]})
        self.cli.paths["a"] = os.path.join(self.home, "hermes-a", "config.yaml")
        self.cli.paths["b"] = os.path.join(self.home, "hermes-b", "config.yaml")
        rc, _, err = self.run_installer("--agent", "hermes")
        self.assertEqual(rc, 0, err)
        for name in ("a", "b"):
            self.assertIn(["/fake/hermes", "-p", name, "config", "get",
                           "hooks", "--json"], self.cli.calls)
            self.assertEqual(len(self.cli.set_calls(name)), 1)
            allowlist = os.path.join(self.home, "hermes-%s" % name,
                                     "shell-hooks-allowlist.json")
            self.assertEqual(self.load(allowlist),
                             {"approvals": [HERMES_APPROVAL]})
        self.assertIn(["/fake/hermes", "config", "get", "hooks", "--json"],
                      self.cli.calls)  # default profile, no -p flag

    def test_non_string_profile_entries_are_noted_and_skipped(self):
        self.make_root()
        self.write_config({"hermes_profiles": ["a", 3]})
        self.cli.paths["a"] = os.path.join(self.home, "hermes-a", "config.yaml")
        rc, _, err = self.run_installer("--agent", "hermes")
        self.assertEqual(rc, 0, err)
        self.assertIn("is not a profile name - ignored", err)
        self.assertIn(["/fake/hermes", "-p", "a", "config", "get", "hooks",
                       "--json"], self.cli.calls)
        self.assertFalse(any(argv[1:3] == ["-p", "3"]
                             for argv in self.cli.calls))

    # --- CHK-05 (8): one broken profile, the rest continue ----------------
    def test_invalid_config_get_fails_profile_and_continues(self):
        self.make_root()
        self.write_config({"hermes_profiles": ["a", "b"]})
        self.cli.raw_hooks["a"] = "not json\n"
        rc, _, err = self.run_installer("--agent", "hermes")
        self.assertEqual(rc, 1)
        self.assertIn("actx init: hermes: profile 'a'", err)
        self.assertIn("did not return JSON", err)
        self.assertIn("actx init: cannot install hermes", err)
        self.assertEqual(self.cli.set_calls("a"), [])
        self.assertEqual(len(self.cli.set_calls("b")), 1)
        self.assertEqual(
            len(self.cli.set_calls(HERMES_DEFAULT_PROFILE)), 1)

    def test_uninstall_invalid_config_get_fails_and_touches_nothing(self):
        self.make_root()
        original = json.dumps({"approvals": [HERMES_APPROVAL]}, indent=2) + "\n"
        with open(self.allowlist, "w", encoding="utf-8") as handle:
            handle.write(original)
        self.cli.raw_hooks[HERMES_DEFAULT_PROFILE] = "{broken"
        rc, _, err = self.run_installer("--agent", "hermes", "--uninstall")
        self.assertEqual(rc, 1)
        self.assertIn("default profile", err)
        self.assertIn("manually", err)
        self.assertIn("cannot uninstall hermes", err)
        self.assertEqual(self.cli.set_calls(), [])
        with open(self.allowlist, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), original)

    # --- CHK-05 (8b): a bad allowlist refuses before any write ------------
    def test_invalid_allowlist_refuses_with_no_writes(self):
        self.make_root()
        self.cli.hooks[HERMES_DEFAULT_PROFILE] = {"pre_tool_call": []}
        original = '{"approvals": [broken]}\n'
        with open(self.allowlist, "w", encoding="utf-8") as handle:
            handle.write(original)
        rc, _, err = self.run_installer("--agent", "hermes")
        self.assertEqual(rc, 1)
        self.assertIn(self.allowlist, err)
        self.assertIn("nothing was written", err)
        self.assertEqual(self.cli.set_calls(), [])
        with open(self.allowlist, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), original)

    def test_allowlist_wrong_shapes_refused(self):
        self.make_root()
        self.cli.hooks[HERMES_DEFAULT_PROFILE] = {"pre_tool_call": []}
        for data in ({"approvals": {}}, {"approvals": ["x"]},
                     {"approvals": None}, [], "x"):
            with self.subTest(data=data):
                self.cli.calls.clear()
                self.write_json(self.allowlist, data)
                rc, _, err = self.run_installer("--agent", "hermes")
                self.assertEqual(rc, 1)
                self.assertEqual(self.cli.set_calls(), [])
                self.assertEqual(self.load(self.allowlist), data)

    # --- CHK-05 (9): autodetect follows the data root ---------------------
    def test_autodetect_follows_the_data_root(self):
        rc, _, err = self.run_installer()
        self.assertEqual(rc, 0)
        self.assertNotIn("hermes", err)
        self.assertEqual(self.run_mock.call_count, 0)
        self.make_root()
        rc, _, err = self.run_installer()
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self.cli.set_calls()), 1)
        self.assertTrue(os.path.exists(self.allowlist))

    # --- CHK-05 (10): --show is a stdlib read ----------------------------
    def test_show_reads_the_allowlist_without_subprocess(self):
        self.make_root()
        self.write_json(self.allowlist, {"approvals": [HERMES_APPROVAL]})
        rc, out, err = self.run_installer("--show")
        self.assertEqual(rc, 0)
        self.assertIn("hermes: installed", out)
        self.assertEqual(self.run_mock.call_count, 0)
        self.write_json(self.allowlist, {"approvals": [
            {"event": "pre_tool_call",
             "command": "/old/bin/actx hook --agent hermes"}]})
        self.assertIn("hermes: not installed",
                      self.run_installer("--show")[1])
        with open(self.allowlist, "w", encoding="utf-8") as handle:
            handle.write("{broken")
        rc, out, err = self.run_installer("--show")
        self.assertEqual(rc, 0)
        self.assertIn("hermes: not installed", out)
        self.assertNotIn("Traceback", err)
        self.assertEqual(self.run_mock.call_count, 0)

    def test_installed_requires_the_exact_current_command(self):
        self.make_root()
        self.assertFalse(installer._installed("hermes"))
        self.write_json(self.allowlist, {"approvals": [HERMES_APPROVAL]})
        self.assertTrue(installer._installed("hermes"))
        self.assertEqual(self.run_mock.call_count, 0)


if __name__ == "__main__":
    unittest.main()
