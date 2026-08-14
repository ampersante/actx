import ast
import os
import unittest

# Pinned symbol sets checked by the AST walk. Keep these exact: the test
# below asserts the sets themselves so a silent narrowing fails loudly.
BANNED_NAMES = {"eval", "exec"}
BANNED_OS_ATTRS = {"system", "popen"}
SUBPROCESS_SHELL_METHODS = {"run", "Popen", "call", "check_call", "check_output"}
SUBPROCESS_IMPLICIT_SHELL = {"getoutput", "getstatusoutput"}

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _is_shell_true(node):
    if not isinstance(node, ast.Constant):
        return False
    if not isinstance(node.value, (bool, int)):
        return False
    return node.value is True or node.value == 1


def _violations(tree):
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in BANNED_NAMES:
            found.add(node.id)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "os" and node.attr in BANNED_OS_ATTRS:
                found.add("os.%s" % node.attr)
            elif node.value.id == "subprocess" and node.attr in SUBPROCESS_IMPLICIT_SHELL:
                found.add("subprocess.%s" % node.attr)
        elif isinstance(node, ast.keyword) and node.arg == "shell" and _is_shell_true(node.value):
            found.add("shell=%s" % node.value.value)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            value = node.func.value
            if isinstance(value, ast.Name):
                if value.id == "os" and attr in BANNED_OS_ATTRS:
                    found.add("os.%s" % attr)
                elif value.id == "subprocess" and attr in SUBPROCESS_IMPLICIT_SHELL:
                    found.add("subprocess.%s" % attr)
                elif value.id == "subprocess" and attr in SUBPROCESS_SHELL_METHODS:
                    for keyword in node.keywords:
                        if keyword.arg == "shell" and _is_shell_true(keyword.value):
                            found.add("subprocess.%s(..., shell=%s)" % (attr, keyword.value.value))
    return found


def _source_paths():
    paths = []
    lib = os.path.join(ROOT, "actx_lib")
    for dirpath, dirnames, filenames in os.walk(lib):
        dirnames[:] = [name for name in dirnames if name != "__pycache__"]
        for name in filenames:
            if name.endswith(".py"):
                paths.append(os.path.join(dirpath, name))
    paths.append(os.path.join(ROOT, "actx"))
    return paths


def _violations_in(source):
    return _violations(ast.parse(source))


class SecurityAstTests(unittest.TestCase):
    def test_checked_symbols_are_pinned(self):
        self.assertEqual(BANNED_NAMES, {"eval", "exec"})
        self.assertEqual(BANNED_OS_ATTRS, {"system", "popen"})
        self.assertEqual(
            SUBPROCESS_SHELL_METHODS,
            {"run", "Popen", "call", "check_call", "check_output"},
        )
        self.assertEqual(SUBPROCESS_IMPLICIT_SHELL, {"getoutput", "getstatusoutput"})

    def test_no_banned_symbols_in_shipping_source(self):
        for path in _source_paths():
            with open(path, "r", encoding="utf-8") as handle:
                source = handle.read()
            violations = _violations(ast.parse(source))
            self.assertEqual(
                violations,
                set(),
                "%s contains banned symbols: %s" % (path, sorted(violations)),
            )

    def test_substituted_eval_is_caught(self):
        self.assertIn("eval", _violations_in("eval('1 + 1')\n"))

    def test_substituted_exec_is_caught(self):
        self.assertIn("exec", _violations_in("exec('x = 1')\n"))

    def test_substituted_os_system_is_caught(self):
        violations = _violations_in("import os\nos.system('ls')\n")
        self.assertIn("os.system", violations)

    def test_substituted_os_popen_is_caught(self):
        violations = _violations_in("import os\nos.popen('ls')\n")
        self.assertIn("os.popen", violations)

    def test_substituted_subprocess_run_shell_true_is_caught(self):
        violations = _violations_in(
            "import subprocess\nsubprocess.run(['ls'], shell=True)\n"
        )
        self.assertIn("subprocess.run(..., shell=True)", violations)

    def test_substituted_subprocess_check_output_shell_one_is_caught(self):
        violations = _violations_in(
            "import subprocess\nsubprocess.check_output(['ls'], shell=1)\n"
        )
        self.assertIn("subprocess.check_output(..., shell=1)", violations)

    def test_substituted_subprocess_getoutput_is_caught(self):
        violations = _violations_in("import subprocess\nsubprocess.getoutput('ls')\n")
        self.assertIn("subprocess.getoutput", violations)


if __name__ == "__main__":
    unittest.main()
