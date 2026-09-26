"""TK-60 STEP-W4: replays a corpus of commands through the OLD (fixture)
rewrite results and the NEW (current) `actx_lib.rewriter.rewrite` engine,
reporting:

  - "new rewrites, old did not" violations (REQ-05 hard stop: must be 0
    before the engine change ships).
  - the loss list: "old rewrote, new does not", grouped by head, each
    entry normalised (every value/positional token -> "<v>"/"<p>") with a
    reason, deduplicated.

stdlib only; contains no history data (corpus paths are passed as
arguments; this file ships no data itself).

Usage:
    python3 tools/replay.py <corpus.json> [--history <history_corpus.json>]
"""
import argparse
import json
import shlex
import sys
from collections import defaultdict

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.dirname(__import__("os").path.abspath(__file__))))

from actx_lib import rewriter  # noqa: E402


def _normalize(command):
    """head + flags, with every value/positional token collapsed to a
    generic placeholder so near-duplicate losses group together."""
    try:
        toks = shlex.split(command)
    except ValueError:
        return command
    if not toks:
        return command
    head = toks[0]
    out = [head]
    for tok in toks[1:]:
        if tok.startswith("-"):
            out.append(tok.split("=", 1)[0] + ("=<v>" if "=" in tok else ""))
        else:
            out.append("<p>")
    return " ".join(out)


def _reason(command):
    try:
        toks = shlex.split(command)
    except ValueError:
        return "unparseable (shlex)"
    if not toks:
        return "empty"
    head = toks[0]
    from actx_lib import rewrite_spec, cli_families
    import os as _os
    if _os.path.basename(head) in cli_families.RUN_PREFIXES:
        inner = cli_families.run_prefix_split(toks)
        if inner is None:
            return "run-prefix: wrapper flags not parseable"
        inner_head = inner[0][0]
        if rewrite_spec.HEAD_SPECS.get(inner_head) is None:
            return f"run-prefix: inner head '{inner_head}' has no confirmed spec"
        return "run-prefix: inner command does not match its spec"
    if head not in rewrite_spec.HEAD_SPECS and toks[0] not in rewrite_spec.HEAD_SPECS:
        return "head has no confirmed spec (excluded entirely)"
    return "a token does not match the head's admitted grammar"


def replay(corpus, label):
    new_admits_extra = []
    losses = defaultdict(lambda: defaultdict(int))
    matched = 0
    total = len(corpus)
    for command, old_result in corpus.items():
        new_result = rewriter.rewrite(command)
        old_rewrote = old_result is not None
        new_rewrote = new_result is not None
        if old_rewrote and new_rewrote:
            matched += 1
        elif (not old_rewrote) and new_rewrote:
            new_admits_extra.append(command)
        elif old_rewrote and not new_rewrote:
            try:
                head = shlex.split(command)[0]
            except ValueError:
                head = "<unparseable>"
            key = (head, _reason(command))
            losses[key][_normalize(command)] += 1
        # both-None: not a loss, not a violation - nothing to report
    print(f"=== replay: {label} ===")
    print(f"corpus size: {total}")
    print(f"both rewrite (matched): {matched}")
    print(f"NEW REWRITES, OLD DID NOT (REQ-05 violation, must be 0): {len(new_admits_extra)}")
    for c in new_admits_extra:
        print(f"  VIOLATION: {c!r}")
    total_losses = sum(sum(v.values()) for v in losses.values())
    print(f"losses (old rewrote, new does not): {total_losses} commands, "
          f"{len(losses)} distinct (head, reason) groups")
    for (head, reason), forms in sorted(losses.items()):
        print(f"  [{head}] {reason} - {sum(forms.values())} commands, "
              f"{len(forms)} distinct normalized forms")
        for form, count in sorted(forms.items()):
            print(f"      {form}  (x{count})")
    return len(new_admits_extra), total_losses


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--history", default=None)
    args = ap.parse_args()

    with open(args.corpus) as fh:
        corpus = json.load(fh)
    violations, _ = replay(corpus, "exact corpus")

    if args.history:
        with open(args.history) as fh:
            hist = json.load(fh)
        replay(hist, "approximate history corpus (local only, unverifiable-marked upstream)")

    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
