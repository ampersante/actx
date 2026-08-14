import os
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.realpath(os.path.join(ROOT, "actx"))


class IntegrationTests(unittest.TestCase):
    def run_actx(self, args, home):
        env = os.environ.copy()
        env["HOME"] = home
        return subprocess.run(
            [ACTX] + args,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_autodetect_only_claude_dir_installs_only_claude(self):
        with tempfile.TemporaryDirectory() as home:
            os.makedirs(os.path.join(home, ".claude"), exist_ok=True)
            p = self.run_actx(["init"], home)
            self.assertEqual(p.returncode, 0, p.stderr)

            self.assertTrue(
                os.path.exists(os.path.join(home, ".claude", "settings.json"))
            )
            for path in (
                os.path.join(home, ".codex", "hooks.json"),
                os.path.join(home, ".config", "opencode", "plugins", "actx.ts"),
                os.path.join(home, ".grok", "AGENTS.md"),
                os.path.join(home, ".cline", "rules", "actx.md"),
                os.path.join(
                    home, ".codeium", "windsurf", "memories", "global_rules.md"
                ),
                os.path.join(home, ".config", "actx", "instructions.md"),
                os.path.join(home, ".aider.conf.yml"),
            ):
                self.assertFalse(os.path.exists(path), path)

    def test_opencode_double_init_writes_one_plugin_file(self):
        with tempfile.TemporaryDirectory() as home:
            for _ in range(2):
                p = self.run_actx(["init", "--agent", "opencode"], home)
                self.assertEqual(p.returncode, 0, p.stderr)

            plugin = os.path.join(home, ".config", "opencode", "plugins", "actx.ts")
            self.assertTrue(os.path.exists(plugin))

            plugin_dir = os.path.dirname(plugin)
            plugin_names = [name for name in os.listdir(plugin_dir) if name.startswith("actx")]
            self.assertEqual(plugin_names, ["actx.ts"])

            with open(plugin, "r", encoding="utf-8") as handle:
                content = handle.read()
            self.assertEqual(content.count("const ACTX = "), 1)
            self.assertEqual(content.count('["rewrite", cmd]'), 1)


if __name__ == "__main__":
    unittest.main()
