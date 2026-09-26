"""TK-60 fix-wave (letter E) unit coverage for tools/ast_identity_check.py
and tools/hook_contract_check.py's ALLOW-LIST MECHANISM - i.e. the CLASS of
behavior ("a monolith statement/corpus command whose top-level name/command
string is explicitly, namedly listed is allowed to differ; anything else is
UNEXPECTED and fails"), not a re-assertion of the current 16/2 literal
names, which would just duplicate the scripts themselves and break every
time a future stream adds another named exception.

Fast and side-effect-free: both modules are pure function/constant
definitions at import time (all git/subprocess work happens inside
`main()`, never on import), so they're loaded directly via
importlib.util.spec_from_file_location - no sys.path package hack, no
`tools/__init__.py`. tools/flag_inventory.py is deliberately NOT imported
here: unlike the other two, it shells out to git/man/kubectl/docker for
every HEAD_SPECS entry at MODULE level (not inside a __main__ guard), so
importing it would run that whole external-tool scan on every `python3 -m
unittest discover tests` - it's exercised by hand instead (see the G/E
fix-wave report), not part of this fast suite.
"""

import ast
import importlib.util
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(ROOT, "tools")


def _load(name, filename):
    path = os.path.join(TOOLS_DIR, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


aic = _load("actx_tools_ast_identity_check", "ast_identity_check.py")
hcc = _load("actx_tools_hook_contract_check", "hook_contract_check.py")


class StmtNameTests(unittest.TestCase):
    """`_stmt_name` is what makes ALLOWED_CHANGED_DEFS a CLASS mechanism
    (any top-level def/assignment whose NAME is listed, not one specific
    AST shape) - covers every statement kind the allow-list needs to name,
    plus the unnameable kinds that must stay held to exact identity."""

    def _first_stmt(self, src):
        return ast.parse(src).body[0]

    def test_function_def_name(self):
        node = self._first_stmt("def _foo(x): return x\n")
        self.assertEqual(aic._stmt_name(node), "_foo")

    def test_async_function_def_name(self):
        node = self._first_stmt("async def _foo(x): return x\n")
        self.assertEqual(aic._stmt_name(node), "_foo")

    def test_class_def_name(self):
        node = self._first_stmt("class _Foo:\n    pass\n")
        self.assertEqual(aic._stmt_name(node), "_Foo")

    def test_single_target_assign_name(self):
        node = self._first_stmt("_FOO = frozenset({'a', 'b'})\n")
        self.assertEqual(aic._stmt_name(node), "_FOO")

    def test_ann_assign_name(self):
        node = self._first_stmt("_FOO: frozenset = frozenset()\n")
        self.assertEqual(aic._stmt_name(node), "_FOO")

    def test_aug_assign_name(self):
        node = self._first_stmt("_FOO += 1\n")
        self.assertEqual(aic._stmt_name(node), "_FOO")

    def test_multi_target_assign_is_unnameable(self):
        # `a = b = 1` - two targets, no single obvious name; must stay held
        # to exact AST identity (never allow-listable by a bare name).
        node = self._first_stmt("a = b = 1\n")
        self.assertIsNone(aic._stmt_name(node))

    def test_tuple_target_assign_is_unnameable(self):
        node = self._first_stmt("a, b = 1, 2\n")
        self.assertIsNone(aic._stmt_name(node))

    def test_bare_expression_is_unnameable(self):
        node = self._first_stmt("_foo()\n")
        self.assertIsNone(aic._stmt_name(node))

    def test_del_is_unnameable(self):
        node = self._first_stmt("del _foo\n")
        self.assertIsNone(aic._stmt_name(node))


class AllowListGatesUnnamedDifferencesTests(unittest.TestCase):
    """Proves the PASS/FAIL split in ast_identity_check.py's main() logic
    is name-driven and would gate an UNRELATED, made-up name exactly the
    same way it gates the real 16 - i.e. it is a general mechanism, not a
    hard-coded acceptance of "whatever the package currently looks like".
    Exercises the same Counter/name-lookup logic main() runs, directly,
    without shelling out to git (no --base/--target involved)."""

    def _partition(self, mono_src, pkg_src, allowed_names):
        mono_stmts = aic._top_level_statements(mono_src, "<mono>")
        pkg_stmts = aic._top_level_statements(pkg_src, "<pkg>")
        from collections import Counter
        mono_counts = Counter(d for _, d in mono_stmts)
        pkg_counts = Counter(d for _, d in pkg_stmts)
        mono_name_by_dump = {d: n for n, d in mono_stmts}
        missing = [d for d, c in mono_counts.items() if pkg_counts.get(d, 0) < c]
        unexpected = [d for d in missing if mono_name_by_dump.get(d) not in allowed_names]
        allowed = [d for d in missing if mono_name_by_dump.get(d) in allowed_names]
        return allowed, unexpected

    def test_named_change_is_allowed(self):
        mono = "def _thing():\n    return 1\n"
        pkg = "def _thing():\n    return 2\n"
        allowed, unexpected = self._partition(mono, pkg, {"_thing"})
        self.assertEqual(len(allowed), 1)
        self.assertEqual(len(unexpected), 0)

    def test_unnamed_change_without_allow_entry_is_unexpected(self):
        mono = "def _thing():\n    return 1\n"
        pkg = "def _thing():\n    return 2\n"
        allowed, unexpected = self._partition(mono, pkg, set())  # empty allow-list
        self.assertEqual(len(allowed), 0)
        self.assertEqual(len(unexpected), 1)

    def test_unrelated_change_not_in_allow_list_is_unexpected(self):
        # allow-listing _thing does not launder a DIFFERENT function's drift
        mono = "def _thing():\n    return 1\n\ndef _other():\n    return 1\n"
        pkg = "def _thing():\n    return 1\n\ndef _other():\n    return 2\n"
        allowed, unexpected = self._partition(mono, pkg, {"_thing"})
        self.assertEqual(len(allowed), 0)
        self.assertEqual(len(unexpected), 1)

    def test_identical_bodies_need_no_allow_entry(self):
        mono = "def _thing():\n    return 1\n"
        pkg = "def _thing():\n    return 1\n"
        allowed, unexpected = self._partition(mono, pkg, set())
        self.assertEqual(len(allowed), 0)
        self.assertEqual(len(unexpected), 0)


class HookContractAllowedCommandsTests(unittest.TestCase):
    """ALLOWED_COMMANDS is the same CLASS mechanism at the corpus-command
    level: a (schema, command) mismatch is allowed only when its command
    string is a named key, never by blanket-trusting any mismatch."""

    def test_allowed_commands_is_nonempty_str_to_str_mapping(self):
        self.assertIsInstance(hcc.ALLOWED_COMMANDS, dict)
        self.assertGreater(len(hcc.ALLOWED_COMMANDS), 0)
        for command, reason in hcc.ALLOWED_COMMANDS.items():
            self.assertIsInstance(command, str)
            self.assertIsInstance(reason, str)
            self.assertTrue(reason, "every allowed command must be justified, never a bare pass")

    def test_unlisted_command_is_not_allowed(self):
        self.assertNotIn("rm -rf /", hcc.ALLOWED_COMMANDS)


if __name__ == "__main__":
    unittest.main()
