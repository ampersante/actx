"""TK-40 golden corpus: kubectl/helm rewriter + hang verdicts.

The fixture (tests/fixtures/golden/kubectl_helm_tk40_verdicts.json) was
recorded MECHANICALLY at the pre-migration HEAD (a4a1a2b, TK-39 state:
`_KUBECTL_RO` == {get, logs}, no helm anywhere) by running rewriter.rewrite()
over the cartesian corpus (get/logs/describe/top/events x {bare, -n prod,
--namespace=prod, -w, -o json, --context ctx}) plus hang_policy.classify()
for the streaming/secret/exec forms. Any behavior change during the TK-40
migration MUST show up as an explicit fixture diff in the commit that
introduces it (H-F10/N-F12a): silent regressions are physically impossible.
"""

import json
import os
import shlex
import unittest

from actx_lib import hang_policy, rewriter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(
    ROOT, "tests", "fixtures", "golden", "kubectl_helm_tk40_verdicts.json"
)


class GoldenVerdictTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURE, encoding="utf-8") as handle:
            cls.data = json.load(handle)

    def test_corpus_is_the_frozen_one(self):
        # The corpus itself is part of the contract: 5 verbs x 6 variants
        # plus the streaming/secret/exec and helm extras.
        self.assertEqual(len(self.data["rewrite"]), 40)
        self.assertEqual(len(self.data["classify"]), 11)

    def test_rewrite_verdicts_match_golden(self):
        for command, expected in self.data["rewrite"].items():
            with self.subTest(command=command):
                self.assertEqual(rewriter.rewrite(command), expected)

    def test_classify_verdicts_match_golden(self):
        for command, expected in self.data["classify"].items():
            with self.subTest(command=command):
                self.assertEqual(
                    hang_policy.classify(shlex.split(command)), expected
                )


if __name__ == "__main__":
    unittest.main()
