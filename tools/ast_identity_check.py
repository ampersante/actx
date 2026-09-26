"""TK-59 STEP-R3(b) (extended by the TK-60 fix-wave, letter E): AST identity
of every top-level statement in the pre-split monolith
(``git show 4383931:actx_lib/security_gate.py``) against the post-split
package (``actx_lib/security_gate/*.py`` at ``--target``, default ``HEAD``).

Requirement (plan.md 2026-09-27-gate-split-allowlist.md, STEP-R3(b)): every
top-level statement of the monolith - definitions, assignments, loops and
``del``, decorators (incl. ``@functools.lru_cache``) - except import
statements and the module docstring, must appear in the package exactly
once with an identical AST. The two authorized back-edges (security_gate.py
:653 and :1299 in the monolith) become a local ``from .engine import ...``
inside the function body during the move; this check normalizes exactly
that one inserted statement out of both sides before comparing, per the
plan's "сравнение с нормализацией их замены".

Since STEP-R3(b) was written, a later, independent, EXPLICITLY-AUTHORIZED
stream (TK-60 STEP-G1..G4, "stream G") deliberately changed the BODY of a
small, named set of functions/tables inside the package for real security
fixes (grep/git-grep pattern exclusion by index not value; find -exec
interpreter value-flag walking; git config value-flag table; git exec-argv
abbreviation table) - this is real, wanted drift from the monolith, not a
split defect. ALLOWED_CHANGED_DEFS below names every one of those
definitions; a monolith statement is only reported as UNEXPECPTED (and
fails the run) when its own top-level name is NOT in that list. The list
was derived MECHANICALLY, not by hand-reading the diff: it is exactly the
"MISSING" set this script itself printed when first run with
--target=HEAD against the unmodified STEP-R3(b) version of this script
(before ALLOWED_CHANGED_DEFS existed) - i.e. every name that is REALLY,
CONCRETELY different between the monolith and the current package, cross-
checked against `git diff 57e64df..HEAD -- actx_lib/security_gate
actx_lib/cli_families.py` (stream G's own commit range) to confirm each
belongs to a G-step, not a silent unrelated drift. cli_families.py itself
is a separate file the package-vs-monolith comparison never reads, so its
new GIT_EXEC_FLAGS table/git_exec_flag_match function need no entry here -
t6_git.py importing it is an ordinary `import` statement, already excluded
from comparison by name.

Usage:
    python3 tools/ast_identity_check.py [--base 4383931] [--target HEAD]

--base names the pre-split monolith commit (a single file at that revision,
via `git show <base>:actx_lib/security_gate.py`).
--target names the revision whose actx_lib/security_gate/*.py package is
compared against it: the literal string "HEAD" (default) reads the package
straight off disk (fast path - assumes a clean, checked-out working tree,
matched to `git rev-parse HEAD`); any other value is resolved via
`git ls-tree --name-only <target> actx_lib/security_gate` + `git show
<target>:<path>` per file, so a target that isn't currently checked out
(another branch, another commit) can be diffed without touching the
working tree.

Exit status: 0 when every monolith statement is present in the package
exactly once (either byte-identical, or under an ALLOWED_CHANGED_DEFS name
whose body was intentionally changed) - i.e. zero UNEXPECTED differences;
non-zero (with every UNEXPECTED mismatch printed) otherwise. Allowed,
named differences are always printed too, so nothing is silently hidden.
"""

import argparse
import ast
import os
import subprocess
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG_DIR = os.path.join(ROOT, "actx_lib", "security_gate")
PKG_REL_DIR = "actx_lib/security_gate"
MONOLITH_PATH = "actx_lib/security_gate.py"

# Mechanically derived (see module docstring): every top-level name in
# actx_lib/security_gate/*.py whose BODY was intentionally changed vs the
# --base monolith by TK-60 stream G (STEP-G1: t1_paths.py grep/git-grep
# pattern-exclusion by index; STEP-G2: t4_destructive.py find -exec
# interpreter value-flag walking; STEP-G3/G4: t6_git.py git-config
# value-flag table + git exec-argv abbreviation table). A name in this set
# is allowed to differ (added, removed, or body-changed) from the
# monolith; any OTHER monolith statement missing from the package is
# UNEXPECTED and fails the run.
ALLOWED_CHANGED_DEFS = {
    # t1_paths.py (STEP-G1): body changed, same name.
    "_check_sensitive_paths": "STEP-G1",
    # t4_destructive.py (STEP-G2): one table's value changed, two new
    # tables/functions added, one existing function's body/signature
    # changed to use them.
    "_FIND_EXEC_INTERPRETERS": "STEP-G2",
    "_INTERPRETER_VALUE_FLAGS": "STEP-G2",
    "_PYTHON_VALUE_FLAGS": "STEP-G2",
    "_interpreter_value_flags": "STEP-G2",
    "_find_exec_script_arg_is_placeholder": "STEP-G2",
    "_check_find_exec_subcommands": "STEP-G2",
    # t6_git.py (STEP-G3): the file-value-flags table was renamed/widened
    # (_GIT_CONFIG_FILE_VALUE_FLAGS -> _GIT_CONFIG_VALUE_FLAGS), the bool
    # table gained the flags that move (--type/--comment/... are no longer
    # silently mis-scanned as the key), a helper was added, and the
    # consuming function's body changed.
    "_GIT_CONFIG_FILE_VALUE_FLAGS": "STEP-G3 (renamed to _GIT_CONFIG_VALUE_FLAGS)",
    "_GIT_CONFIG_VALUE_FLAGS": "STEP-G3",
    "_GIT_CONFIG_BOOL_FLAGS": "STEP-G3",
    "_git_config_value_flag_attached": "STEP-G3",
    "_git_config_is_write": "STEP-G3",
    # t6_git.py (STEP-G4): the old literal exec-argv-flag tuple was
    # replaced by a lookup into cli_families.GIT_EXEC_FLAGS (a separate
    # file this check never reads), the verb set is now derived from it,
    # and the matcher function gained a `verb` parameter.
    "_GIT_EXEC_ARGV_FLAGS": "STEP-G4 (replaced by cli_families.GIT_EXEC_FLAGS)",
    "_GIT_EXEC_FLAG_VERBS": "STEP-G4",
    "_has_git_exec_argv_flag": "STEP-G4",
    "_check_high_risk_git": "STEP-G4",
}


def _git_show(rev, path):
    out = subprocess.run(
        ["/usr/bin/git", "show", f"{rev}:{path}"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return out.stdout


def _git_ls_py_files(rev, rel_dir):
    # `<rev>:<dir>` (colon form) is a tree-ish for the SUBTREE at that path,
    # so `--name-only` lists its direct children (bare filenames); the
    # plain `git ls-tree <rev> <dir>` form instead matches `<dir>` as a
    # pathspec against rev's root tree and prints just that one entry name
    # - the wrong result for "every file in the package directory".
    out = subprocess.run(
        ["/usr/bin/git", "ls-tree", "--name-only", f"{rev}:{rel_dir}"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return sorted(
        line for line in out.stdout.splitlines() if line.endswith(".py")
    )


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


def _stmt_name(node):
    """The top-level name a statement defines, when it has one obvious
    single name (function/class def, or an assignment/annotated-assignment/
    aug-assignment to a single bare Name) - None otherwise (bare
    expressions, multi-target assignments, `del`, loops, ...), which keeps
    those statements held to exact AST identity with no allow-listing."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
        return node.target.id
    return None


def _top_level_statements(source, filename):
    """Returns [(name_or_None, dump)] for every top-level statement except
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
        stmts.append((_stmt_name(node), _normalize(node)))
    return stmts


def _read_package_sources(target):
    """Yields (fname, source) for every actx_lib/security_gate/*.py file at
    `target` - straight off disk for the "HEAD" fast path (default), via
    `git ls-tree` + `git show` for any other explicit target."""
    if target == "HEAD":
        for fname in sorted(os.listdir(PKG_DIR)):
            if fname.endswith(".py"):
                with open(os.path.join(PKG_DIR, fname), encoding="utf-8") as f:
                    yield fname, f.read()
        return
    for fname in _git_ls_py_files(target, PKG_REL_DIR):
        yield fname, _git_show(target, f"{PKG_REL_DIR}/{fname}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="4383931",
                         help="pre-split monolith revision (default: 4383931)")
    parser.add_argument("--target", default="HEAD",
                         help="revision whose actx_lib/security_gate/ package to compare "
                              "(default: HEAD, read straight off the working tree)")
    args = parser.parse_args()

    monolith_src = _git_show(args.base, MONOLITH_PATH)
    monolith_stmts = _top_level_statements(monolith_src, MONOLITH_PATH)
    print(f"Monolith ({args.base}:{MONOLITH_PATH}): {len(monolith_stmts)} top-level statements (excl. imports/docstring)")

    package_stmts = []
    for fname, src in _read_package_sources(args.target):
        stmts = _top_level_statements(src, fname)
        package_stmts.extend(stmts)
        print(f"  {fname}: {len(stmts)} top-level statements (excl. imports/docstring)")

    print(f"Package total ({args.target}): {len(package_stmts)} top-level statements (excl. imports/docstring)")

    mono_dumps = [d for _, d in monolith_stmts]
    pkg_dumps = [d for _, d in package_stmts]
    mono_name_by_dump = {d: n for n, d in monolith_stmts}
    pkg_name_by_dump = {d: n for n, d in package_stmts}

    mono_counts = Counter(mono_dumps)
    pkg_counts = Counter(pkg_dumps)

    missing = []
    for dump, count in mono_counts.items():
        if pkg_counts.get(dump, 0) < count:
            missing.append((dump, count, pkg_counts.get(dump, 0)))

    extra = []
    for dump, count in pkg_counts.items():
        if mono_counts.get(dump, 0) < count:
            extra.append((dump, count, mono_counts.get(dump, 0)))

    allowed_missing = [m for m in missing if mono_name_by_dump.get(m[0]) in ALLOWED_CHANGED_DEFS]
    unexpected_missing = [m for m in missing if mono_name_by_dump.get(m[0]) not in ALLOWED_CHANGED_DEFS]

    # The requirement (STEP-R3(b)) is one-directional: every monolith
    # statement present exactly once (or explicitly, namedly allowed to
    # differ). New package-glue statements (e.g. __init__.py's __all__
    # list, or the NEW body of an ALLOWED_CHANGED_DEFS name) are not a
    # violation - they are reported as informational "extra" only, never a
    # failure.
    ok = not unexpected_missing

    if allowed_missing:
        print(f"\nALLOWED, NAMED differences from stream G ({len(allowed_missing)}) - "
              f"old monolith body no longer present, replaced under the SAME top-level "
              f"name by an intentional fix (see ALLOWED_CHANGED_DEFS):")
        for dump, mono_n, pkg_n in allowed_missing:
            name = mono_name_by_dump.get(dump)
            print(f"  {name} ({ALLOWED_CHANGED_DEFS.get(name)}): expected {mono_n}x old body, found {pkg_n}x unchanged")

    if unexpected_missing:
        print(f"\nUNEXPECTED differences (must be 0) - MISSING/UNDER-DUPLICATED in package ({len(unexpected_missing)}):")
        for dump, mono_n, pkg_n in unexpected_missing:
            name = mono_name_by_dump.get(dump)
            print(f"  name={name!r} expected {mono_n}x, found {pkg_n}x: {dump[:200]}")

    if extra:
        allowed_extra = [e for e in extra if pkg_name_by_dump.get(e[0]) in ALLOWED_CHANGED_DEFS]
        other_extra = [e for e in extra if pkg_name_by_dump.get(e[0]) not in ALLOWED_CHANGED_DEFS]
        print(f"\nNew package-glue/replacement statements not (byte-identically) in the monolith "
              f"(informational, never a failure - one-directional requirement) ({len(extra)}):")
        for dump, pkg_n, mono_n in allowed_extra:
            name = pkg_name_by_dump.get(dump)
            print(f"  ALLOWED new body of {name} ({ALLOWED_CHANGED_DEFS.get(name)}): found {pkg_n}x")
        for dump, pkg_n, mono_n in other_extra:
            name = pkg_name_by_dump.get(dump)
            print(f"  {name!r}: found {pkg_n}x: {dump[:200]}")

    if ok:
        print(f"\nAST IDENTITY OK: all {len(monolith_stmts)} monolith top-level statements present in the "
              f"package exactly once - byte-identical, or under one of the {len(ALLOWED_CHANGED_DEFS)} "
              f"named, intentional stream-G exceptions above (0 unexpected differences).")
    else:
        print(f"\nAST IDENTITY CHECK FAILED: {len(unexpected_missing)} unexpected difference(s).")
        sys.exit(1)


if __name__ == "__main__":
    main()
