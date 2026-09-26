"""Deterministic, stdlib-only L7 Security Gatekeeper for actx hook (TK-59
package split of the former actx_lib/security_gate.py monolith).

Protects agentic coding sessions (Claude Code, Codex CLI) against:
- T1: Sensitive file & credential access (local exfiltration)
- T2: Out-of-band network exfiltration
- T3: Shell obfuscation, dynamic eval & remote pipeline execution
- T4: Destructive OS mutations & persistence hijacking
- T5: Supply chain & insecure package lifecycle installations
- T6: High-risk git/cargo/cloud-infra mutations requiring human confirmation ("ask")
- T7: Action space backstop & prohibited file operations (§26a core-rules)

Zero external dependencies (Python 3.14 stdlib only).
Evaluation latency strictly < 1.0 ms wall time.

Public API (REQ-02, TK-59 plan section 2, derived from an exact grep of
every consumer - see tools/gate_corpus_extract.py's neighbor commands and
the plan's E-007 evidence entry): ``evaluate_security``, ``SecurityDecision``,
``T6_ASK_TABLE``, ``_T6_NON_CLOUD_ASK_TABLE``, ``_quick_check_hit``,
``_RE_SENSITIVE_QUICK_CHECK``, and the ``sql_verbs`` module itself (patched
by tests/test_sql_gate.py:128 as ``security_gate.sql_verbs``). Every other
name lives in its owning submodule only.
"""

from actx_lib import sql_verbs

from .common import SecurityDecision, _quick_check_hit, _RE_SENSITIVE_QUICK_CHECK
from .engine import evaluate_security
from .t6_tools import T6_ASK_TABLE, _T6_NON_CLOUD_ASK_TABLE

__all__ = [
    "evaluate_security",
    "SecurityDecision",
    "T6_ASK_TABLE",
    "_T6_NON_CLOUD_ASK_TABLE",
    "_quick_check_hit",
    "_RE_SENSITIVE_QUICK_CHECK",
    "sql_verbs",
]
