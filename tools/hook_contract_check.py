"""TK-59 STEP-R3(e) (extended by the TK-60 fix-wave, letter E): hook.process()
byte-identity between the pre-split monolith (default: commit 4383931) and
`--target` (default: HEAD), for both hook schemas (Claude/Codex
`tool_input`, Antigravity `toolCall`), over the whole gate corpus
(tests/fixtures/gate_corpus.json), fixed HOME.

Technique: two subprocess runs of the sibling helper hook_contract_runner.py,
one with PYTHONPATH pointed at a full actx_lib/ snapshot materialized from
`--base` via `git archive`, one pointed at `--target` (the working tree
directly for the "HEAD" fast path - default; another `git archive`
materialization for any other explicit revision) - never two `actx_lib`
packages imported in the same interpreter.

STEP-R3(e) (2026-09-27, TK-59) was written when `actx_lib/rewriter.py` was
provably untouched since `--base` (a hard `git diff --stat` guard refused to
run otherwise) - the ONLY thing STEP-R3(e) needed to prove was that the
security_gate package split changed nothing. Since then, two further,
independently-authorized streams intentionally changed real behavior on top
of that split: TK-60 stream W (STEP-W1..W3) replaced the rewriter's engine
outright (a closed-grammar engine, designed and separately verified
elsewhere - tests/test_rewrite_spec.py, tools/replay.py - to be
behaviorally equivalent to the old one), and streams G/W6 changed a few
named SecurityDecision-level classifications on purpose (see
ALLOWED_COMMANDS below). The old hard refusal would now permanently refuse
to ever run again, since `actx_lib/rewriter.py` provably (and correctly)
differs from any `--base` that predates STEP-W1 - that is the stale
assumption this fix-wave (letter E) corrects: the guard below now WARNS
(never silently) instead of exiting, and the two real, live-verified,
NAMED command-level differences that whole-corpus run actually produces are
called out explicitly instead of being hidden by the guard never letting
the comparison run at all.

Usage:
    python3 tools/hook_contract_check.py [--base 4383931] [--target HEAD]

Exit status: 0 when every (schema, command) pair in the corpus is
byte-identical between --base and --target, OR its (schema, command) is one
of the explicitly NAMED ALLOWED_COMMANDS entries below (0 UNEXPECTED
differences); non-zero (with every UNEXPECTED mismatch printed) otherwise.
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

# Named, explicitly-justified (schema, command) pairs allowed to differ
# between --base=4383931 and --target=HEAD, found by actually running this
# check against the whole corpus with the old hard-refuse guard downgraded
# to a warning (never hand-picked from reading the diff) - each is real,
# individually re-verified below, not "GNU/BSD"-style noise:
#
#   sqlite3 --cmd '.load ./x' db 'select 1'
#     TK-60 STEP-W6 (091804c): before W6, sql_verbs only recognized the
#     single-dash `-cmd` spelling as sqlite3's command-payload flag, so the
#     classifier's "no explicit read-only class" reason text cited the
#     WRONG token (the positional 'db') as the payload; after W6, the
#     double-dash `--cmd` spelling is recognized too and the reason
#     correctly cites the actual SQL/meta-command payload ('.load ./x').
#     The DECISION itself is unchanged both sides ("ask") - only the
#     human-readable reason text differs. A real, intentional, in-scope fix.
#
#   uv run bash -c id
#     Predates this fix-wave's G/W6 changes entirely: TK-60 STEP-W1..W3
#     (17d512e/49e90f6/ea4ae21) replaced the old ad-hoc rewriter with the
#     closed-grammar engine already at commit 0abac64 (the base this
#     fix-wave starts from) - `git diff --stat 4383931 -- actx_lib/
#     rewriter.py` shows the file completely rewritten. The new engine's
#     "actx: command outside actx policy - deferred to user confirmation"
#     fallback (visible in the antigravity-schema result; the claude-schema
#     result is `None`, i.e. "no hook output/unmodified" - also a valid,
#     different-shaped result) replaces the old rewriter's unconditional
#     auto-rewrite of `uv run bash -c id` to `actx uv run bash -c id`. This
#     is NOT one of stream G/W6's named changes (it touches no file G/W6
#     touched) - it is a real, pre-existing (as of this fix-wave's own
#     starting commit) consequence of the closed-grammar migration, named
#     here for full transparency rather than silently rolled into "G/W6".
ALLOWED_COMMANDS = {
    "sqlite3 --cmd '.load ./x' db 'select 1'": "TK-60 STEP-W6 (091804c): reason text now cites the correct SQL payload token; decision unchanged",
    "uv run bash -c id": "predates G/W6: TK-60 STEP-W1..W3 closed-grammar rewriter migration, already at this fix-wave's own base commit (0abac64)",
}


def _materialize_tree(rev, dest_dir):
    proc = subprocess.run(
        ["/usr/bin/git", "archive", rev, "--", "actx_lib"],
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


def _run_at(rev, tmp_prefix):
    """Runs the corpus through `rev`'s actx_lib: HEAD reads the working
    tree directly (fast path - assumes a clean, checked-out tree); any
    other explicit revision is materialized via `git archive` first, same
    technique as `--base`."""
    if rev == "HEAD":
        return _run(ROOT)
    with tempfile.TemporaryDirectory(prefix=tmp_prefix) as tmp:
        _materialize_tree(rev, tmp)
        print("Materialized actx_lib/ @ %s into %s" % (rev, tmp))
        return _run(tmp)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="4383931",
                         help="pre-split monolith revision (default: 4383931)")
    parser.add_argument("--target", default="HEAD",
                         help="revision to compare against --base (default: HEAD, "
                              "read straight off the working tree)")
    args = parser.parse_args()

    diff = subprocess.run(
        ["/usr/bin/git", "diff", "--stat", args.base, args.target, "--", "actx_lib/rewriter.py"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    )
    if diff.stdout.strip():
        print("NOTE: actx_lib/rewriter.py differs between %s and %s (see module "
              "docstring: expected once TK-60 stream W's closed-grammar migration "
              "has landed) - comparing hook.process() output directly; any real "
              "difference this causes must be one of the NAMED ALLOWED_COMMANDS "
              "below or the run fails." % (args.base, args.target))
        print(diff.stdout)
    else:
        print("actx_lib/rewriter.py unchanged between %s and %s." % (args.base, args.target))

    old_out = _run_at(args.base, "actx_hook_contract_base_")
    new_out = _run_at(args.target, "actx_hook_contract_target_")

    if len(old_out) != len(new_out):
        print("MISMATCH: different number of results (%d old vs %d new)" % (len(old_out), len(new_out)))
        sys.exit(1)

    unexpected = []
    allowed = []
    per_schema = {"claude": [0, 0], "antigravity": [0, 0]}  # [match, mismatch]
    for (old_schema, old_cmd, old_res), (new_schema, new_cmd, new_res) in zip(old_out, new_out):
        assert old_schema == new_schema and old_cmd == new_cmd, "runner ordering drifted"
        old_bytes = json.dumps(old_res, sort_keys=True)
        new_bytes = json.dumps(new_res, sort_keys=True)
        if old_bytes == new_bytes:
            per_schema[old_schema][0] += 1
            continue
        per_schema[old_schema][1] += 1
        entry = (old_schema, old_cmd, old_res, new_res)
        if old_cmd in ALLOWED_COMMANDS:
            allowed.append(entry)
        else:
            unexpected.append(entry)

    total = len(old_out)
    total_mismatch = sum(v[1] for v in per_schema.values())
    print("Compared %d (schema, command) pairs (%d unique commands x 2 schemas)." % (total, total // 2))
    for schema, (m, mm) in per_schema.items():
        print("  %s: %d byte-identical, %d mismatched" % (schema, m, mm))

    if allowed:
        print("\nALLOWED, NAMED differences (%d) - see ALLOWED_COMMANDS in this script:" % len(allowed))
        for schema, cmd, old_res, new_res in allowed:
            print("  schema=%s command=%r (%s)" % (schema, cmd, ALLOWED_COMMANDS[cmd]))
            print("    old=%r" % (old_res,))
            print("    new=%r" % (new_res,))

    if unexpected:
        print("\nUNEXPECTED differences (must be 0) (%d, showing up to 20):" % len(unexpected))
        for schema, cmd, old_res, new_res in unexpected[:20]:
            print("  schema=%s command=%r" % (schema, cmd))
            print("    old=%r" % (old_res,))
            print("    new=%r" % (new_res,))
        sys.exit(1)

    print("\nHOOK CONTRACT OK: %d/%d byte-identical, %d named-allowed, 0 unexpected."
          % (total - total_mismatch, total, len(allowed)))


if __name__ == "__main__":
    main()
