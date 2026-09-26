"""TK-59 STEP-R1/R3: security_gate monolith -> package equivalence.

Loads tests/fixtures/gate_corpus.json (built by tools/gate_corpus_extract.py
against the pre-split monolith, commit 4383931) and re-evaluates every
command against the CURRENT actx_lib.security_gate under the same fixed
environment recorded in the fixture. REQ-01: decision, category and reason
must be byte-identical - a passing run here is the mechanical proof that the
TK-59 package split changed no gate behavior.
"""

import json
import os
import unittest

from actx_lib import security_gate

FIXTURE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "gate_corpus.json"
)


def _load_fixture():
    with open(FIXTURE_PATH, encoding="utf-8") as f:
        return json.load(f)


class GateEquivalenceTests(unittest.TestCase):
    """Full-corpus decision/category/reason equivalence, fixed environment."""

    @classmethod
    def setUpClass(cls):
        cls.fixture = _load_fixture()

    def setUp(self):
        self._orig_home = os.environ.get("HOME")
        os.environ["HOME"] = self.fixture["home"]

    def tearDown(self):
        if self._orig_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = self._orig_home

    def test_corpus_size_is_nonempty(self):
        # Guards against a silently-empty/truncated fixture making the
        # equivalence loop below vacuously pass.
        self.assertGreater(len(self.fixture["corpus"]), 3000)

    def test_full_corpus_decision_identity(self):
        corpus = self.fixture["corpus"]
        mismatches = []
        for command, expected in corpus.items():
            exp_decision, exp_category, exp_reason = expected
            dec = security_gate.evaluate_security(command)
            if (dec.decision, dec.category, dec.reason) != (
                exp_decision,
                exp_category,
                exp_reason,
            ):
                mismatches.append(
                    (command, expected, [dec.decision, dec.category, dec.reason])
                )
        if mismatches:
            lines = [
                "%r: expected=%r actual=%r" % (cmd, exp, act)
                for cmd, exp, act in mismatches[:20]
            ]
            self.fail(
                "%d/%d corpus commands changed decision after the split "
                "(showing up to 20):\n%s"
                % (len(mismatches), len(corpus), "\n".join(lines))
            )


if __name__ == "__main__":
    unittest.main()
