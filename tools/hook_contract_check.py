"""TK-59 STEP-R3(e): hook.process() byte-identity between the pre-split
monolith (default: commit 4383931) and the current branch, for both hook
schemas (Claude/Codex `tool_input`, Antigravity `toolCall`), over the whole
gate corpus (tests/fixtures/gate_corpus.json), fixed HOME, same rewriter (R
never touches actx_lib/rewriter.py - verified by `git diff --stat <base> --
actx_lib/rewriter.py` being empty before this check runs).

Not committed as a fixture: the result depends on actx_lib/rewriter.py,
which TK-60 (stream W) changes later - only the STEP-R3 run against the
still-unchanged rewriter is meaningful. The per-run counters are the
evidence (plan.md STEP-R3(e): "результат - счётчик в журнал").

Technique: two subprocess runs of tools_data/hook_contract_runner.py (or the
copy alongside this script; kept in tools/ so it participates in git only
once), one with PYTHONPATH pointed at a full actx_lib/ snapshot materialized
from the base revision via `git archive`, one with PYTHONPATH pointed at
this checkout - never two `actx_lib` packages imported in the same
interpreter.

Usage:
    python3 tools/hook_contract_check.py [--base 4383931]
"""

import argparse
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE_PATH = os.path.join(ROOT, "tests", "fixtures", "gate_corpus.json")
RUNNER_PATH = os.path.join(ROOT, "tools", "hook_contract_runner.py")


def _materialize_old_tree(base_rev, dest_dir):
    proc = subprocess.run(
        ["/usr/bin/git", "archive", base_rev, "--", "actx_lib"],
        cwd=ROOT, capture_output=True, check=True,
    )
    with tarfile.open(fileobj=io.BytesIO(proc.stdout), mode="r|") as tf:
        tf.extractall(dest_dir, filter="data")


def _run(pythonpath):
    env = os.environ.copy()
    env["PYTHONPATH"] = pythonpath
    proc = subprocess.run(
        [sys.executable, RUNNER_PATH, FIXTURE_PATH],
        cwd=ROOT, env=env, capture_output=True, text=True, check=True,
    )
    return json.loads(proc.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="4383931")
    args = parser.parse_args()

    diff = subprocess.run(
        ["/usr/bin/git", "diff", "--stat", args.base, "--", "actx_lib/rewriter.py"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    if diff.stdout.strip():
        print("REFUSING: actx_lib/rewriter.py differs from %s - this check only "
              "proves anything when the rewriter is unchanged (STEP-R scope):"
              % args.base)
        print(diff.stdout)
        sys.exit(2)
    print("actx_lib/rewriter.py unchanged vs %s: git diff --stat is empty." % args.base)

    with tempfile.TemporaryDirectory(prefix="actx_hook_contract_old_") as tmp:
        _materialize_old_tree(args.base, tmp)
        print("Materialized actx_lib/ @ %s into %s" % (args.base, tmp))
        old_out = _run(tmp)

    new_out = _run(ROOT)

    if len(old_out) != len(new_out):
        print("MISMATCH: different number of results (%d old vs %d new)" % (len(old_out), len(new_out)))
        sys.exit(1)

    mismatches = []
    per_schema = {"claude": [0, 0], "antigravity": [0, 0]}  # [match, mismatch]
    for (old_schema, old_cmd, old_res), (new_schema, new_cmd, new_res) in zip(old_out, new_out):
        assert old_schema == new_schema and old_cmd == new_cmd, "runner ordering drifted"
        old_bytes = json.dumps(old_res, sort_keys=True)
        new_bytes = json.dumps(new_res, sort_keys=True)
        if old_bytes == new_bytes:
            per_schema[old_schema][0] += 1
        else:
            per_schema[old_schema][1] += 1
            mismatches.append((old_schema, old_cmd, old_res, new_res))

    total = len(old_out)
    total_mismatch = sum(v[1] for v in per_schema.values())
    print("Compared %d (schema, command) pairs (%d unique commands x 2 schemas)." % (total, total // 2))
    for schema, (m, mm) in per_schema.items():
        print("  %s: %d byte-identical, %d mismatched" % (schema, m, mm))

    if mismatches:
        print("\nMismatches (showing up to 20):")
        for schema, cmd, old_res, new_res in mismatches[:20]:
            print("  schema=%s command=%r" % (schema, cmd))
            print("    old=%r" % (old_res,))
            print("    new=%r" % (new_res,))
        sys.exit(1)

    print("\nHOOK CONTRACT OK: %d/%d byte-identical across both schemas." % (total - total_mismatch, total))


if __name__ == "__main__":
    main()
