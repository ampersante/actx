"""TK-59 STEP-R3(a): every global name each security_gate submodule loads is
either a builtin, imported in that module, or defined in that module - a
mechanical guard against the exact class of bug the split risks (a forgotten
cross-module import that the outer fail-open in evaluate_security would
silently turn into 'allow' instead of raising).

Static, AST-only: no module is imported/executed by this test.
"""

import ast
import builtins
import os
import unittest

PKG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "actx_lib", "security_gate",
)

_BUILTIN_NAMES = set(dir(builtins)) | {"__name__", "__file__", "__doc__", "__package__"}


def _module_files():
    return sorted(
        f for f in os.listdir(PKG_DIR)
        if f.endswith(".py")
    )


def _target_names(target):
    """Names bound by an assignment/for/with/comprehension target (handles
    Name, Tuple/List destructuring and Starred)."""
    names = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_target_names(elt))
    elif isinstance(target, ast.Starred):
        names.extend(_target_names(target.value))
    # ast.Attribute / ast.Subscript targets bind no new name.
    return names


class _ModuleBindingCollector(ast.NodeVisitor):
    """Collects every name bound at MODULE level: imports, function/class
    defs, assignment targets (incl. AnnAssign/AugAssign/For/With), and
    comprehension-free walrus targets at module level."""

    def __init__(self):
        self.bound = set()

    def visit_Import(self, node):
        for alias in node.names:
            self.bound.add((alias.asname or alias.name).split(".")[0])

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.bound.add(alias.asname or alias.name)

    def visit_FunctionDef(self, node):
        self.bound.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.bound.add(node.name)

    def visit_Assign(self, node):
        for t in node.targets:
            self.bound.update(_target_names(t))

    def visit_AnnAssign(self, node):
        self.bound.update(_target_names(node.target))

    def visit_AugAssign(self, node):
        self.bound.update(_target_names(node.target))

    def visit_For(self, node):
        self.bound.update(_target_names(node.target))
        for stmt in node.body + node.orelse:
            self.visit(stmt)

    def visit_With(self, node):
        for item in node.items:
            if item.optional_vars is not None:
                self.bound.update(_target_names(item.optional_vars))
        for stmt in node.body:
            self.visit(stmt)

    def visit_If(self, node):
        for stmt in node.body + node.orelse:
            self.visit(stmt)

    # Delete does not need special handling for this check's purpose: a
    # name deleted after use at module level was still bound when defined,
    # and functions defined earlier already captured it as a global name
    # (Python resolves globals at call time from the module dict, but a
    # correctness bug from calling-after-delete would be a pre-existing
    # monolith bug, not something the split could introduce - out of scope
    # here; see t6_tools.py's `del _head, _spec` after building T6_ASK_TABLE).


class _FunctionFreeNameFinder(ast.NodeVisitor):
    """Within one function (or nested function) body, finds Name loads not
    bound by: builtins, module-level bindings, function parameters, or any
    local assignment/for/with/except/comprehension target in the function
    or an enclosing function (closures) up to module scope."""

    def __init__(self, module_bound):
        self.module_bound = module_bound
        self.scopes = []  # stack of sets; index 0 nearest
        self.unresolved = []

    def _bound_anywhere(self, name):
        if name in _BUILTIN_NAMES or name in self.module_bound:
            return True
        return any(name in scope for scope in self.scopes)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load) and not self._bound_anywhere(node.id):
            self.unresolved.append(node.id)

    def visit_Attribute(self, node):
        # Only the root of an attribute chain is a Name load we care about;
        # descend to find it (handles a.b.c()).
        self.visit(node.value)

    def _collect_params(self, args: ast.arguments):
        names = set()
        for group in (args.posonlyargs, args.args, args.kwonlyargs):
            names.update(a.arg for a in group)
        if args.vararg:
            names.add(args.vararg.arg)
        if args.kwarg:
            names.add(args.kwarg.arg)
        return names

    def _visit_function(self, node):
        scope = self._collect_params(node.args)
        # Pre-scan the function body for locally-bound names (assignments,
        # for/with/except targets, nested defs, comprehension results are
        # scoped separately below) so forward references within the same
        # function resolve too (matches Python's own "local if assigned
        # anywhere in the function" rule).
        scope |= self._prescan_locals(node.body)
        self.scopes.insert(0, scope)
        for stmt in node.body:
            self.visit(stmt)
        self.scopes.pop(0)

    def visit_FunctionDef(self, node):
        self._visit_function(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        scope = self._collect_params(node.args)
        self.scopes.insert(0, scope)
        self.visit(node.body)
        self.scopes.pop(0)

    def _prescan_locals(self, stmts):
        names = set()

        class _Scanner(ast.NodeVisitor):
            def visit_Import(self, n):
                for alias in n.names:
                    names.add((alias.asname or alias.name).split(".")[0])

            def visit_ImportFrom(self, n):
                for alias in n.names:
                    names.add(alias.asname or alias.name)

            def visit_Assign(self, n):
                for t in n.targets:
                    names.update(_target_names(t))
                self.generic_visit(n)

            def visit_AnnAssign(self, n):
                names.update(_target_names(n.target))
                self.generic_visit(n)

            def visit_AugAssign(self, n):
                names.update(_target_names(n.target))
                self.generic_visit(n)

            def visit_NamedExpr(self, n):
                names.update(_target_names(n.target))
                self.generic_visit(n)

            def visit_For(self, n):
                names.update(_target_names(n.target))
                self.generic_visit(n)

            def visit_With(self, n):
                for item in n.items:
                    if item.optional_vars is not None:
                        names.update(_target_names(item.optional_vars))
                self.generic_visit(n)

            def visit_ExceptHandler(self, n):
                if n.name:
                    names.add(n.name)
                self.generic_visit(n)

            def visit_FunctionDef(self, n):
                names.add(n.name)
                # Do not descend: a nested function's own locals are its
                # own scope, not this function's.

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_ClassDef(self, n):
                names.add(n.name)

            def visit_Lambda(self, n):
                pass  # own scope, do not descend

            def visit_ListComp(self, n):
                pass  # own scope in Python 3

            visit_SetComp = visit_ListComp
            visit_DictComp = visit_ListComp
            visit_GeneratorExp = visit_ListComp

        for stmt in stmts:
            _Scanner().visit(stmt)
        return names

    def _visit_comprehension_owner(self, node, elts):
        # Comprehensions have their own scope in Python 3: generator targets
        # are bound only within the comprehension.
        scope = set()
        for gen in node.generators:
            scope.update(_target_names(gen.target))
        self.scopes.insert(0, scope)
        for gen in node.generators:
            self.visit(gen.iter)
            for cond in gen.ifs:
                self.visit(cond)
        for elt in elts:
            self.visit(elt)
        self.scopes.pop(0)

    def visit_ListComp(self, node):
        self._visit_comprehension_owner(node, [node.elt])

    def visit_SetComp(self, node):
        self._visit_comprehension_owner(node, [node.elt])

    def visit_GeneratorExp(self, node):
        self._visit_comprehension_owner(node, [node.elt])

    def visit_DictComp(self, node):
        self._visit_comprehension_owner(node, [node.key, node.value])


def _check_module(path):
    with open(path, encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src, filename=path)

    collector = _ModuleBindingCollector()
    for stmt in tree.body:
        collector.visit(stmt)
    module_bound = collector.bound

    unresolved = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            finder = _FunctionFreeNameFinder(module_bound)
            finder._visit_function(node)
            if finder.unresolved:
                unresolved[node.name] = sorted(set(finder.unresolved))
    return unresolved


class GatePackageNameResolutionTests(unittest.TestCase):
    def test_every_submodule_resolves_all_global_names(self):
        failures = {}
        for fname in _module_files():
            path = os.path.join(PKG_DIR, fname)
            unresolved = _check_module(path)
            if unresolved:
                failures[fname] = unresolved
        self.assertEqual(
            failures, {},
            "unresolved global names (missing import - would fail-open to "
            "'allow' at runtime instead of raising): %r" % (failures,),
        )

    def test_package_has_expected_module_set(self):
        self.assertEqual(
            set(_module_files()),
            {
                "__init__.py", "common.py", "t1_paths.py", "t2_t3.py",
                "t4_destructive.py", "t5_supply.py", "t6_git.py",
                "t6_tools.py", "t6_sql.py", "t7_action.py", "engine.py",
            },
        )


if __name__ == "__main__":
    unittest.main()
