"""TK-41 golden corpus: docker verdicts captured before the migration.

tests/fixtures/docker_tk41_golden.json is a mechanical dump produced by
running rewriter.rewrite() / hang_policy.classify() over the corpus on the
pre-migration base (a4a1a2b) and committed BEFORE any cli_families
migration (wave-2 plan H-F10/N-F12a, TK-50 precedent). A diff between the
live verdicts and the dump means the migration silently changed observable
behavior.

Cases whose change the TK-41 spec prescribes move into PRESCRIBED_CHANGES
in the same commit that changes them; the test then additionally requires
the dump to still hold the pre-migration value (provenance proof) and
pins the new verdict. Everything outside PRESCRIBED_CHANGES must match the
dump byte-for-byte forever.
"""

import json
import os
import shlex
import unittest

from actx_lib import hang_policy, rewriter

GOLDEN_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures",
    "docker_tk41_golden.json",
)

# case -> (dumped pre-migration verdict, post-migration verdict).
# Filled in by the commits that implement the prescribed change; a case
# lands here only when the TK-41 spec explicitly mandates the new verdict.
PRESCRIBED_CHANGES = {}


def _load_dump():
    with open(GOLDEN_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _rewrite_verdict(command):
    out = rewriter.rewrite(command)
    if out is None:
        return "none"
    if out == "actx " + command:
        return "prefix"
    return "unexpected"


def _hang_verdict(command):
    return hang_policy.classify(shlex.split(command))


class DockerGoldenCorpusTests(unittest.TestCase):
    def _check(self, mode, verdict_fn):
        dump = _load_dump()[mode]
        self.assertTrue(dump)
        for command, recorded in sorted(dump.items()):
            with self.subTest(mode=mode, command=command):
                actual = verdict_fn(command)
                if command in PRESCRIBED_CHANGES:
                    old, new = PRESCRIBED_CHANGES[command]
                    # The dump must keep proving its pre-migration origin.
                    self.assertEqual(recorded, old, command)
                    self.assertEqual(actual, new, command)
                else:
                    self.assertEqual(actual, recorded, command)

    def test_rewrite_verdicts_match_dump(self):
        self._check("rewrite", _rewrite_verdict)

    def test_hang_verdicts_match_dump(self):
        self._check("hang", _hang_verdict)


if __name__ == "__main__":
    unittest.main()
