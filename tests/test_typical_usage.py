"""TK-60: committed synthetic regression fixture, sourced from the three
per-group research proposals' "must rewrite" / "must NOT rewrite" example
lists (git-gh, build-data-cloud, files-tests - 667 distinct commands after
dedup). No history data; every command here is a synthetic example
authored by the research passes, not derived from real user history
(REQ-11 compliant).

`tests/fixtures/typical_usage.json` maps each command to the CURRENT
engine's VERIFIED actual result (not the proposals' raw aspirational
claim) - most commands match the proposal's own expectation exactly, but
a documented minority diverge for one of three reasons (all catalogued in
the stream report, not silently absorbed here):

  1. Named owner decisions: `xcodebuild -scheme/-destination` gating,
     `tsc` without a `require_any_of` no-emit gate, and `next build`'s
     spec are kept AS TODAY; `dbt run`/`build` are REMOVED (warehouse-
     mutating, data-integrity criterion) - `dbt test`/`compile`/`list`/
     `ls` stay admitted. `git commit --amend` stays excluded.
  2. Pre-existing architecture limits outside this module's scope: the
     top-level metacharacter guard in `rewriter.rewrite()` rejects any
     command containing `{`/`}`/`(`/`)`/`|` before per-head dispatch even
     runs (e.g. `docker ps --format '{{.Names}}'`, `rg -l "x" | sort`,
     `find . \\( -name x -o -name y \\)`) - these are not spec gaps.
  3. A handful of small, accepted compression losses and two confirmed
     internal contradictions in the source proposals (their own flag
     table said EXCLUDE for a flag their pasted code admitted, or vice
     versa) - resolved in favor of the safer/more-cited direction.

This test pins the frozen result exactly (a plain equality check, same
pattern as `test_rewrite_equivalence.py`); it exists to catch a future
regression in this specific synthetic set, not to re-litigate the
proposals' own expectations."""
import json
import os
import unittest

from actx_lib.rewriter import rewrite

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "typical_usage.json")


class TypicalUsageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURE) as fh:
            cls.fixture = json.load(fh)

    def test_fixture_is_nonempty(self):
        self.assertGreater(len(self.fixture), 600)

    def test_every_command_matches(self):
        mismatches = []
        for command, expected in self.fixture.items():
            actual = rewrite(command)
            if actual != expected:
                mismatches.append((command, expected, actual))
        self.assertEqual(
            mismatches, [],
            f"{len(mismatches)} typical-usage command(s) no longer match: "
            f"{mismatches[:10]}",
        )


if __name__ == "__main__":
    unittest.main()
