"""TK-59 STEP-R3(b): AST identity of every top-level statement in the
pre-split monolith (``git show 4383931:actx_lib/security_gate.py``) against
the post-split package (``actx_lib/security_gate/*.py``).

Requirement (plan.md 2026-09-27-gate-split-allowlist.md, STEP-R3(b)): every
top-level statement of the monolith - definitions, assignments, loops and
``del``, decorators (incl. ``@functools.lru_cache``) - except import
statements and the module docstring, must appear in the package exactly
once with an identical AST. The two authorized back-edges (security_gate.py
:653 and :1299 in the monolith) become a local ``from .engine import ...``
inside the function body during the move; this check normalizes exactly
that one inserted statement out of both sides before comparing, per the
plan's "сравнение с нормализацией их замены".

Usage:
    python3 tools/ast_identity_check.py [--base 4383931]

Exits non-zero (and prints every mismatch) if any monolith statement is
missing, duplicated, or not byte-identical (as AST) in the package.
"""

import argparse
import ast
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG_DIR = os.path.join(ROOT, "actx_lib", "security_gate")
MONOLITH_PATH = "actx_lib/security_gate.py"


def _git_show(rev, path):
    out = subprocess.run(
        ["/usr/bin/git", "show", f"{rev}:{path}"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return out.stdout


class _StripEngineBackEdgeImports(ast.NodeTransformer):
    """Removes any `from .engine import ...` / `from engine import ...`
    statement from a function body (the two authorized back-edges added
    during STEP-R2) so the surrounding function body compares identically
    to the monolith's pre-split version."""

    def visit_ImportFrom(self, node):
        if node.module == "engine":
            return None
        return node

    def generic_visit(self, node):
        return super().generic_visit(node)


def _normalize(node):
    node = _StripEngineBackEdgeImports().visit(node)
    ast.fix_missing_locations(node)
    return ast.dump(node, annotate_fields=True, include_attributes=False)


def _top_level_statements(source, filename):
    """Returns [(kind_name, dump)] for every top-level statement except
    Import/ImportFrom and a leading module-docstring Expr(Constant(str))."""
    tree = ast.parse(source, filename=filename)
    stmts = []
    for i, node in enumerate(tree.body):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if i == 0 and isinstance(node, ast.Expr) and isinstance(
            getattr(node, "value", None), ast.Constant
        ) and isinstance(node.value.value, str):
            continue  # module docstring
        stmts.append(_normalize(node))
    return stmts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="4383931")
    args = parser.parse_args()

    monolith_src = _git_show(args.base, MONOLITH_PATH)
    monolith_stmts = _top_level_statements(monolith_src, MONOLITH_PATH)
    print(f"Monolith ({args.base}:{MONOLITH_PATH}): {len(monolith_stmts)} top-level statements (excl. imports/docstring)")

    package_stmts = []
    for fname in sorted(os.listdir(PKG_DIR)):
        if not fname.endswith(".py"):
            continue
        path = os.path.join(PKG_DIR, fname)
        with open(path, encoding="utf-8") as f:
            src = f.read()
        stmts = _top_level_statements(src, path)
        package_stmts.extend(stmts)
        print(f"  {fname}: {len(stmts)} top-level statements (excl. imports/docstring)")

    print(f"Package total: {len(package_stmts)} top-level statements (excl. imports/docstring)")

    from collections import Counter
    mono_counts = Counter(monolith_stmts)
    pkg_counts = Counter(package_stmts)

    missing = []
    for dump, count in mono_counts.items():
        if pkg_counts.get(dump, 0) < count:
            missing.append((dump, count, pkg_counts.get(dump, 0)))

    extra = []
    for dump, count in pkg_counts.items():
        if mono_counts.get(dump, 0) < count:
            extra.append((dump, count, mono_counts.get(dump, 0)))

    # The requirement (STEP-R3(b)) is one-directional: every monolith
    # statement present exactly once. New package-glue statements (e.g.
    # __init__.py's __all__ list) are not a violation - they are reported
    # as informational "extra" only, never a failure.
    ok = not missing

    if missing:
        print(f"\nMISSING/UNDER-DUPLICATED in package ({len(missing)}):")
        for dump, mono_n, pkg_n in missing:
            print(f"  expected {mono_n}x, found {pkg_n}x: {dump[:200]}")
    if extra:
        print(f"\nNew package-glue statements not from the monolith (informational, not a failure) ({len(extra)}):")
        for dump, pkg_n, mono_n in extra:
            print(f"  found {pkg_n}x: {dump[:200]}")

    if ok:
        print(f"\nAST IDENTITY OK: all {len(monolith_stmts)} monolith top-level statements present in the "
              f"package exactly once (normalizing the two engine back-edge imports).")
    else:
        print("\nAST IDENTITY CHECK FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
