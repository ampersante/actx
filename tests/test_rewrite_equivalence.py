"""TK-60 STEP-W1: exact rewriter corpus snapshot, taken on master `4383931`
(pre-TK-60 rewriter.py) before the closed-grammar engine change.

`tests/fixtures/rewrite_corpus.json` maps every distinct command string
observed as (a) an argument to a direct `rewriter.rewrite()` call anywhere
in this test suite (including golden-fixture loops) and (b) the decoded
command embedded in the stdin of every `subprocess.run([ACTX, "hook"],
input=...)` call in this test suite (both the Claude/Codex and Antigravity
hook JSON schemas) - to the OLD rewriter's result for that exact string.
Extraction method: `actx_lib.rewriter.rewrite` and `subprocess.run` were
monkey-patched in a throwaway, out-of-repo script (not committed - it is
not product code and is not needed after this snapshot exists) that ran
the full `python3 -m unittest discover tests` suite once under
instrumentation and recorded every call's argument/result plus the
caller's `file:line`.

Call-site completeness (verified when the snapshot was taken, not
re-checked by this test - the snapshot is a frozen artifact): every static
source location matching `rewriter.rewrite(`/bare `rewrite(` or
`subprocess.run([ACTX, "hook"]` under `tests/` fired at least once during
the instrumented run; the only non-firing grep hits were prose/docstring/
JSON-comment mentions of "rewriter.rewrite()", not real call sites.

This test pins the OLD engine's behavior byte-for-byte; TK-60's later
engine change is checked against it by `tools/replay.py` (STEP-W4), not by
editing this file - a corpus entry only changes when the plan record says
so (STEP-W6, or an owner-approved loss)."""
import json
import os
import unittest

from actx_lib.rewriter import rewrite

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "rewrite_corpus.json")


class RewriteEquivalenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURE) as fh:
            cls.corpus = json.load(fh)

    def test_corpus_is_nonempty(self):
        self.assertGreater(len(self.corpus), 700)

    def test_every_corpus_entry_matches(self):
        mismatches = []
        for command, expected in self.corpus.items():
            actual = rewrite(command)
            if actual != expected:
                mismatches.append((command, expected, actual))
        self.assertEqual(
            mismatches, [],
            f"{len(mismatches)} corpus command(s) no longer match: "
            f"{mismatches[:10]}",
        )


if __name__ == "__main__":
    unittest.main()
