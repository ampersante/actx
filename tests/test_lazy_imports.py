import json
import os
import subprocess
import sys
import tempfile
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

# CLI filter path (`actx <registry-head> ...`): REGISTRY is a top-level
# import in filters/__init__.py (TK-42 H-F14), so every filter module -
# mobile_filter included - loads here. The hook/rewrite paths above never
# import the filters package.
CLI_FILTER_PATH_MODULES = {
    "actx_lib",
    "actx_lib.cli",
    "actx_lib.cli_families",
    "actx_lib.config",
    "actx_lib.filters",
    "actx_lib.filters.compact_profiles",
    "actx_lib.filters.git_filter",
    "actx_lib.filters.infra_filter",
    "actx_lib.filters.json_compactor",
    "actx_lib.filters.linter_filter",
    "actx_lib.filters.mobile_filter",
    "actx_lib.filters.package_filter",
    "actx_lib.filters.read_filter",
    "actx_lib.filters.smart_filter",
    "actx_lib.filters.system_filter",
    "actx_lib.filters.test_runner_filter",
    "actx_lib.filters.tree_filter",
    "actx_lib.hang_policy",
    "actx_lib.redaction",
    "actx_lib.rewriter",
    "actx_lib.sql_verbs",
    "actx_lib.runner",
    "actx_lib.tracking",
    "actx_lib.user_filter",
}


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
             "actx_lib.rewriter", "actx_lib.sql_verbs"},
        )

    def test_rewrite_path_imports_only_allowed(self):
        self.assertEqual(
            self.run_path(["rewrite", "git status"]),
            {"actx_lib", "actx_lib.cli", "actx_lib.cli_families",
             "actx_lib.rewriter", "actx_lib.sql_verbs"},
        )

    def test_hook_path_imports_only_allowed(self):
        self.assertEqual(
            self.run_path(["hook"], stdin_text=HOOK_JSON),
            {
                "actx_lib",
                "actx_lib.cli",
                "actx_lib.cli_families",
                "actx_lib.rewriter",
                "actx_lib.sql_verbs",
                "actx_lib.hook",
                "actx_lib.security_gate",
            },
        )

    def test_cli_filter_path_imports_mobile_filter(self):
        # TK-42 (H-F14): mobile REGISTRY entries are ordinary top-level
        # imports, so the CLI path pulls in actx_lib.filters.mobile_filter.
        # Bare `xcodebuild` is never-wrap (interactive signing prompts): the
        # dispatch is proven deterministically without executing any binary.
        # HOME is isolated - the refusal records tracking telemetry.
        with tempfile.TemporaryDirectory() as home:
            env = os.environ.copy()
            env["HOME"] = home
            proc = subprocess.run(
                [sys.executable, "-c", PRINT_MODULES, "xcodebuild"],
                capture_output=True,
                text=True,
                cwd=ROOT,
                env=env,
                stdin=subprocess.DEVNULL,
            )
        self.assertEqual(proc.returncode, 125, proc.stderr)
        modules = {
            line
            for line in proc.stderr.splitlines()
            if line.startswith("actx_lib")
        }
        self.assertEqual(modules, CLI_FILTER_PATH_MODULES)


if __name__ == "__main__":
    unittest.main()
