import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HOOK_JSON = json.dumps({"tool_name": "Bash", "tool_input": {"command": "git status"}})

PRINT_MODULES = (
    "import sys\n"
    "from actx_lib import cli\n"
    "rc = cli.main(sys.argv)\n"
    "print('\\n'.join(sorted(m for m in sys.modules if m.startswith('actx_lib'))), file=sys.stderr)\n"
    "raise SystemExit(rc)\n"
)

IMPORT_ONLY = (
    "import sys\n"
    "from actx_lib import cli\n"
    "print('\\n'.join(sorted(m for m in sys.modules if m.startswith('actx_lib'))), file=sys.stderr)\n"
)


class LazyImportTests(unittest.TestCase):
    def run_path(self, args, stdin_text=None):
        env = os.environ.copy()
        proc = subprocess.run(
            [sys.executable, "-c", PRINT_MODULES] + args,
            input=stdin_text,
            capture_output=True,
            text=True,
            cwd=ROOT,
            env=env,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return {
            line
            for line in proc.stderr.splitlines()
            if line.startswith("actx_lib")
        }

    def test_import_cli_does_not_import_filters(self):
        proc = subprocess.run(
            [sys.executable, "-c", IMPORT_ONLY],
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        modules = {
            line
            for line in proc.stderr.splitlines()
            if line.startswith("actx_lib")
        }
        self.assertEqual(
            modules,
            {"actx_lib", "actx_lib.cli", "actx_lib.cli_families",
             "actx_lib.rewriter"},
        )

    def test_rewrite_path_imports_only_allowed(self):
        self.assertEqual(
            self.run_path(["rewrite", "git status"]),
            {"actx_lib", "actx_lib.cli", "actx_lib.cli_families",
             "actx_lib.rewriter"},
        )

    def test_hook_path_imports_only_allowed(self):
        self.assertEqual(
            self.run_path(["hook"], stdin_text=HOOK_JSON),
            {
                "actx_lib",
                "actx_lib.cli",
                "actx_lib.cli_families",
                "actx_lib.rewriter",
                "actx_lib.hook",
                "actx_lib.security_gate",
            },
        )


if __name__ == "__main__":
    unittest.main()
