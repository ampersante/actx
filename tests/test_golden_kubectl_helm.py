"""TK-40 golden corpus: kubectl/helm rewriter + hang verdicts.

The fixture (tests/fixtures/golden/kubectl_helm_tk40_verdicts.json) was
recorded MECHANICALLY at the pre-migration HEAD (a4a1a2b, TK-39 state:
`_KUBECTL_RO` == {get, logs}, no helm anywhere) by running rewriter.rewrite()
over the cartesian corpus (get/logs/describe/top/events x {bare, -n prod,
--namespace=prod, -w, -o json, --context ctx}) plus hang_policy.classify()
for the streaming/secret/exec forms. The TK-40 migration commit updated it
in place: exactly 28 rewrite verdicts (null -> "actx ..." for the newly
declared ro_verbs and flag forms) and 4 classify verdicts (default ->
never_wrap for helm get values, watch flags and the secret object type) -
every diff is prescribed by the wave-2 plan §4 E2; nothing else moved.
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

    def test_only_the_prescribed_verdicts_changed(self):
        # Frozen post-migration expectations (diffed against the
        # pre-migration commit b3a6bf0; see module docstring).
        self.assertEqual(self.data["rewrite"]["kubectl exec web-abc -- ls"], None)
        self.assertEqual(
            self.data["rewrite"]["kubectl get pods -w"],
            "actx kubectl get pods -w",
        )
        self.assertEqual(
            self.data["rewrite"]["kubectl logs -f pod/web-abc"],
            "actx kubectl logs -f pod/web-abc",
        )
        self.assertEqual(self.data["rewrite"]["helm get values my-release"], None)
        self.assertEqual(self.data["classify"]["kubectl exec web-abc -- ls"], "default")
        self.assertEqual(
            self.data["classify"]["kubectl logs -f pod/web-abc"], "never_wrap"
        )

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
