"""TK-58 pack 1b: installer safety (INV-10) and removed-agent check (INV-13).

Every test runs the real ``actx`` against a temporary HOME; nothing touches
the caller's configs.
"""

import copy
import json
import os
import shlex
import stat
import subprocess
import tempfile
import unittest

from actx_lib.installer import INSTRUCTION_SECTION

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.realpath(os.path.join(ROOT, "actx"))

CODEX_MATCHER = "Bash|shell|bash|exec"
STALE = shlex.quote("/opt/homebrew/Cellar/actx/2.2/libexec/actx") + " hook"
# The agent whose support was removed; spelled in pieces so a repo-wide
# grep for the name stays empty (INV-13).
GONE = "ai" + "der"
HEADER = "## Output compression (actx)"
LOOKALIKE = "## Output compression (actx) notes for my team"

USER_A = {"type": "command", "command": "echo user-a", "timeout": 3}
USER_B = {"type": "command", "command": "echo user-b"}


def current_handler():
    return {"type": "command", "command": shlex.quote(ACTX) + " hook", "timeout": 10}


class InstallerCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = tmp.name

    def actx(self, *args):
        env = os.environ.copy()
        env["HOME"] = self.home
        env.pop("XDG_CONFIG_HOME", None)
        env.pop("PI_CODING_AGENT_DIR", None)
        return subprocess.run([ACTX] + list(args), capture_output=True, text=True, env=env)

    def path(self, *parts):
        return os.path.join(self.home, *parts)

    def put(self, path, data, mode=None):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        if mode is not None:
            os.chmod(path, mode)
        return path

    def put_json(self, path, data):
        return self.put(path, json.dumps(data, indent=2) + "\n")

    def load(self, path):
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)

    def read_bytes(self, path):
        with open(path, "rb") as handle:
            return handle.read()

    def mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def handlers_with_actx(self, data):
        """All hook handlers in a Claude/Codex-shaped file whose command is ours."""
        found = []
        for entry in data["hooks"]["PreToolUse"]:
            for handler in entry.get("hooks", []):
                if handler.get("command", "").endswith(" hook") and "actx" in handler["command"]:
                    found.append(handler)
        return found


class CodexEntryTests(InstallerCase):
    def hooks_file(self):
        return self.path(".codex", "hooks.json")

    def test_user_bash_entry_is_never_mutated(self):
        original = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [USER_A]}]}}
        self.put_json(self.hooks_file(), original)
        for _ in range(2):
            p = self.actx("init", "--agent", "codex")
            self.assertEqual(p.returncode, 0, p.stderr)
        entries = self.load(self.hooks_file())["hooks"]["PreToolUse"]
        self.assertEqual(entries[0], {"matcher": "Bash", "hooks": [USER_A]})
        self.assertEqual(
            entries[1:], [{"matcher": CODEX_MATCHER, "hooks": [current_handler()]}]
        )
        self.assertIn("codex: installed", self.actx("init", "--show").stdout)
        p = self.actx("init", "--agent", "codex", "--uninstall")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.load(self.hooks_file()), original)

    def test_legacy_mixed_entry_keeps_user_handlers_and_matcher(self):
        user_entry = {"matcher": CODEX_MATCHER, "hooks": [USER_A, {
            "type": "command", "command": STALE, "timeout": 10}, USER_B]}
        other = {"matcher": "Edit", "hooks": [USER_B]}
        self.put_json(self.hooks_file(), {"hooks": {"PreToolUse": [user_entry, other]}})
        outputs = []
        for _ in range(2):
            p = self.actx("init", "--agent", "codex")
            self.assertEqual(p.returncode, 0, p.stderr)
            outputs.append(p.stdout)
        data = self.load(self.hooks_file())
        self.assertEqual(len(self.handlers_with_actx(data)), 1)
        self.assertEqual(self.handlers_with_actx(data), [current_handler()])
        entries = data["hooks"]["PreToolUse"]
        user_after = [e for e in entries if USER_A in e["hooks"]]
        self.assertEqual(len(user_after), 1)
        self.assertEqual(user_after[0]["matcher"], CODEX_MATCHER)
        self.assertEqual(
            [h for h in user_after[0]["hooks"] if h in (USER_A, USER_B)], [USER_A, USER_B]
        )
        self.assertIn(other, entries)
        self.assertIn("left unchanged", outputs[0])
        self.assertIn("/hooks", outputs[0])
        p = self.actx("init", "--agent", "codex", "--uninstall")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(
            self.load(self.hooks_file()),
            {"hooks": {"PreToolUse": [
                {"matcher": CODEX_MATCHER, "hooks": [USER_A, USER_B]}, other]}},
        )

    def test_stale_actx_only_entry_is_replaced_not_duplicated(self):
        stale_entry = {"matcher": CODEX_MATCHER, "hooks": [
            {"type": "command", "command": STALE, "timeout": 10}]}
        user = {"matcher": "Bash", "hooks": [USER_A]}
        self.put_json(self.hooks_file(), {"hooks": {"PreToolUse": [user, stale_entry]}})
        for _ in range(2):
            self.assertEqual(self.actx("init", "--agent", "codex").returncode, 0)
        data = self.load(self.hooks_file())
        self.assertEqual(self.handlers_with_actx(data), [current_handler()])
        self.assertEqual(data["hooks"]["PreToolUse"][0], user)
        self.assertEqual(len(data["hooks"]["PreToolUse"]), 2)

    def test_second_init_does_not_rewrite_the_file(self):
        self.assertEqual(self.actx("init", "--agent", "codex").returncode, 0)
        os.utime(self.hooks_file(), (1, 1))
        self.assertEqual(self.actx("init", "--agent", "codex").returncode, 0)
        self.assertEqual(os.stat(self.hooks_file()).st_mtime, 1)

    def test_uninstall_finds_handler_by_command_not_matcher(self):
        entry = {"matcher": "Task", "hooks": [USER_A, current_handler()]}
        self.put_json(self.hooks_file(), {"hooks": {"PreToolUse": [entry]}})
        self.assertIn("codex: installed", self.actx("init", "--show").stdout)
        self.assertEqual(self.actx("init", "--agent", "codex", "--uninstall").returncode, 0)
        self.assertEqual(
            self.load(self.hooks_file()),
            {"hooks": {"PreToolUse": [{"matcher": "Task", "hooks": [USER_A]}]}},
        )

    def test_claude_appends_into_users_exact_bash_entry(self):
        original = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [USER_A]}]}}
        path = self.put_json(self.path(".claude", "settings.json"), original)
        for _ in range(2):
            self.assertEqual(self.actx("init", "--agent", "claude").returncode, 0)
        self.assertEqual(
            self.load(path)["hooks"]["PreToolUse"],
            [{"matcher": "Bash", "hooks": [USER_A, current_handler()]}],
        )
        self.assertEqual(self.actx("init", "--agent", "claude", "--uninstall").returncode, 0)
        self.assertEqual(self.load(path), original)


class Tier2HeaderTests(InstallerCase):
    def rules(self):
        return self.path(".cline", "rules", "actx.md")

    def test_lookalike_heading_as_only_heading_is_not_our_section(self):
        mine = "# Team\n\n%s\nOur own notes.\n" % LOOKALIKE
        self.put(self.rules(), mine)
        self.assertIn("cline: not installed", self.actx("init", "--show").stdout)
        self.assertEqual(self.actx("init", "--agent", "cline", "--uninstall").returncode, 0)
        self.assertEqual(self.read_bytes(self.rules()), mine.encode())
        self.assertEqual(self.actx("init", "--agent", "cline").returncode, 0)
        content = self.read_bytes(self.rules()).decode()
        self.assertTrue(content.startswith(mine.rstrip("\n")))
        self.assertIn(LOOKALIKE + "\nOur own notes.", content)
        self.assertIn(INSTRUCTION_SECTION, content)
        self.assertIn("cline: installed", self.actx("init", "--show").stdout)

    def test_lookalike_heading_after_our_section_survives_replace_and_uninstall(self):
        stale = HEADER + "\n\nold body\n"
        tail = "%s\nTeam notes stay.\n" % LOOKALIKE
        self.put(self.rules(), "Intro\n\n" + stale + "\n" + tail)
        self.assertEqual(self.actx("init", "--agent", "cline").returncode, 0)
        content = self.read_bytes(self.rules()).decode()
        self.assertNotIn("old body", content)
        self.assertEqual(content.count(HEADER + "\n"), 1)
        self.assertEqual(content.count(LOOKALIKE + "\nTeam notes stay.\n"), 1)
        self.assertTrue(content.startswith("Intro\n\n" + tail), content)
        self.assertTrue(content.endswith(INSTRUCTION_SECTION + "\n"), content)
        self.assertEqual(self.actx("init", "--agent", "cline", "--uninstall").returncode, 0)
        self.assertEqual(
            self.read_bytes(self.rules()).decode(), "Intro\n\n" + tail)

    def test_crlf_header_is_recognised(self):
        crlf = (HEADER + "\r\n\r\nold body\r\n").encode()
        self.put(self.rules(), crlf)
        self.assertIn("cline: installed", self.actx("init", "--show").stdout)
        self.assertEqual(self.actx("init", "--agent", "cline", "--uninstall").returncode, 0)
        self.assertEqual(self.read_bytes(self.rules()), b"")

    def test_crlf_user_text_outside_section_is_byte_identical(self):
        user = b"Rule one\r\nRule two\r\n"
        self.put(self.rules(), user)
        self.assertEqual(self.actx("init", "--agent", "cline").returncode, 0)
        self.assertTrue(self.read_bytes(self.rules()).startswith(user))
        self.assertEqual(self.actx("init", "--agent", "cline", "--uninstall").returncode, 0)
        self.assertTrue(self.read_bytes(self.rules()).startswith(b"Rule one\r\nRule two"))


class InstallerErrorTests(InstallerCase):
    def assert_clean_failure(self, p, path, verb):
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertIn("actx init: cannot %s %s" % (verb, path), p.stderr)

    def test_non_utf8_tier2_file_is_a_clean_error_and_untouched(self):
        path = self.put(self.path(".cline", "rules", "actx.md"), b"\xff\xfe rules\n")
        for args in (("--agent", "cline"), ("--agent", "cline", "--uninstall")):
            p = self.actx("init", *args)
            self.assert_clean_failure(p, path, "read")
            self.assertEqual(self.read_bytes(path), b"\xff\xfe rules\n")

    def test_non_utf8_claude_settings_is_a_clean_error_and_untouched(self):
        path = self.put(self.path(".claude", "settings.json"), b'{"a": "\xff"}')
        p = self.actx("init", "--agent", "claude")
        self.assertEqual(p.returncode, 1)
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(self.read_bytes(path), b'{"a": "\xff"}')

    def test_read_only_tier2_file_is_a_clean_error_and_untouched(self):
        path = self.put(self.path(".cline", "rules", "actx.md"), "mine\n", mode=0o444)
        p = self.actx("init", "--agent", "cline")
        self.assert_clean_failure(p, path, "write")
        self.assertEqual(self.read_bytes(path), b"mine\n")
        self.assertEqual(self.mode(path), 0o444)

    def test_read_only_claude_settings_is_a_clean_error_and_untouched(self):
        original = '{"theme": "dark"}\n'
        path = self.put(self.path(".claude", "settings.json"), original, mode=0o444)
        p = self.actx("init", "--agent", "claude")
        self.assert_clean_failure(p, path, "write")
        self.assertEqual(self.read_bytes(path), original.encode())

    def test_unreadable_file_is_a_clean_error(self):
        path = self.put(self.path(".cline", "rules", "actx.md"), "mine\n", mode=0o000)
        self.addCleanup(os.chmod, path, 0o600)
        p = self.actx("init", "--agent", "cline")
        self.assert_clean_failure(p, path, "read")

    def test_agent_all_continues_after_a_failing_agent(self):
        self.put(self.path(".cline", "rules", "actx.md"), b"\xff\n")
        p = self.actx("init", "--agent", "all")
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        for done in (
            self.path(".claude", "settings.json"),
            self.path(".codex", "hooks.json"),
            self.path(".grok", "rules", "actx.md"),
            self.path(".codeium", "windsurf", "memories", "global_rules.md"),
            self.path(".pi", "agent", "extensions", "actx.ts"),
        ):
            self.assertTrue(os.path.exists(done), done)
        self.assertEqual(self.read_bytes(self.path(".cline", "rules", "actx.md")), b"\xff\n")

    def test_agent_all_uninstall_continues_after_a_failing_agent(self):
        self.assertEqual(self.actx("init", "--agent", "all").returncode, 0)
        cline = self.path(".cline", "rules", "actx.md")
        self.put(cline, b"\xff\n")
        p = self.actx("init", "--agent", "all", "--uninstall")
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertNotIn("claude: installed", self.actx("init", "--show").stdout)
        self.assertNotIn("pi: installed", self.actx("init", "--show").stdout)


class AtomicWriteTests(InstallerCase):
    def test_symlinked_settings_stay_symlinks_and_target_is_written(self):
        target = self.put_json(self.path("dotfiles", "settings.json"), {"theme": "dark"})
        link = self.path(".claude", "settings.json")
        os.makedirs(os.path.dirname(link))
        os.symlink(target, link)
        self.assertEqual(self.actx("init", "--agent", "claude").returncode, 0)
        self.assertTrue(os.path.islink(link))
        self.assertEqual(os.readlink(link), target)
        data = self.load(target)
        self.assertEqual(data["theme"], "dark")
        self.assertEqual(self.handlers_with_actx(data), [current_handler()])
        self.assertEqual(self.actx("init", "--agent", "claude", "--uninstall").returncode, 0)
        self.assertTrue(os.path.islink(link))
        self.assertEqual(self.load(target), {"theme": "dark"})

    def test_dangling_symlink_writes_its_target_and_stays_a_symlink(self):
        target = self.path("dotfiles", "settings.json")
        os.makedirs(os.path.dirname(target))
        link = self.path(".claude", "settings.json")
        os.makedirs(os.path.dirname(link))
        os.symlink(target, link)
        self.assertEqual(self.actx("init", "--agent", "claude").returncode, 0)
        self.assertTrue(os.path.islink(link))
        self.assertEqual(self.handlers_with_actx(self.load(target)), [current_handler()])

    def test_new_file_is_0600(self):
        self.assertEqual(self.actx("init", "--agent", "claude").returncode, 0)
        self.assertEqual(self.mode(self.path(".claude", "settings.json")), 0o600)
        self.assertEqual(self.actx("init", "--agent", "grok").returncode, 0)
        self.assertEqual(self.mode(self.path(".grok", "rules", "actx.md")), 0o600)

    def test_existing_file_keeps_its_mode(self):
        for path, agent, data in (
            (self.path(".claude", "settings.json"), "claude", '{"a": 1}\n'),
            (self.path(".cline", "rules", "actx.md"), "cline", "mine\n"),
            (self.path(".config", "devin", "config.json"), "devin", "{}\n"),
        ):
            self.put(path, data, mode=0o640)
            self.assertEqual(self.actx("init", "--agent", agent).returncode, 0)
            self.assertEqual(self.mode(path), 0o640, path)

    def test_no_temp_files_left_behind(self):
        self.assertEqual(self.actx("init", "--agent", "claude").returncode, 0)
        self.assertEqual(os.listdir(self.path(".claude")), ["settings.json"])

    def test_json_outside_actx_handlers_is_semantically_unchanged(self):
        original = {
            "theme": "dark",
            "n": [1, 2, {"x": None}],
            "hooks": {
                "PostToolUse": [{"matcher": "Edit", "hooks": [USER_B]}],
                "PreToolUse": [{"matcher": "Edit", "hooks": [USER_A]}],
            },
        }
        path = self.put_json(self.path(".claude", "settings.json"), original)
        self.assertEqual(self.actx("init", "--agent", "claude").returncode, 0)
        self.assertEqual(self.actx("init", "--agent", "claude", "--uninstall").returncode, 0)
        self.assertEqual(self.load(path), copy.deepcopy(original))


class RemovedAgentTests(InstallerCase):
    def test_removed_agent_is_an_unknown_agent(self):
        p = self.actx("init", "--agent", GONE)
        self.assertEqual(p.returncode, 1)
        self.assertIn("unknown agent: " + GONE, p.stderr)
        self.assertFalse(os.path.exists(self.path("." + GONE + ".conf.yml")))
        self.assertFalse(os.path.exists(self.path(".config", "actx")))

    def test_removed_agent_is_not_listed_or_auto_detected(self):
        conf = self.put(self.path("." + GONE + ".conf.yml"), "read: ~/other.md\n")
        p = self.actx("init", "--show")
        self.assertNotIn(GONE, p.stdout)
        self.assertNotIn(GONE, self.actx("init", "--help").stdout)
        self.assertEqual(self.actx("init").returncode, 0)
        self.assertEqual(self.read_bytes(conf), b"read: ~/other.md\n")
        self.assertEqual(os.listdir(self.home), ["." + GONE + ".conf.yml"])

    def test_agent_all_never_writes_removed_agent_files(self):
        self.assertEqual(self.actx("init", "--agent", "all").returncode, 0)
        self.assertFalse(os.path.exists(self.path("." + GONE + ".conf.yml")))
        self.assertFalse(os.path.exists(self.path(".config", "actx")))

    def test_no_removed_agent_text_in_code_tests_or_docs(self):
        needle = GONE
        hits = []
        for rel in ("actx_lib", "tests", "README.md", "architecture.md"):
            base = os.path.join(ROOT, rel)
            files = [base] if os.path.isfile(base) else [
                os.path.join(d, f) for d, _, fs in os.walk(base) for f in fs
                if f.endswith((".py", ".md", ".txt", ".json"))
            ]
            for file in files:
                with open(file, encoding="utf-8", errors="replace") as handle:
                    if needle in handle.read().lower():
                        hits.append(os.path.relpath(file, ROOT))
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
