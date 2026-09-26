"""actx security gate - T6: high-risk SQL operations (ask confirmation)
(TK-59 split).

``sql_verbs`` is imported as a module and always addressed by attribute
(``sql_verbs.<name>``) so that tests/test_sql_gate.py:128's
``mock.patch.object(security_gate.sql_verbs, "danger_reason", ...)`` reaches
the exact call this module makes (REQ-02) - both names are the same module
object cached in sys.modules, so patching the attribute through the
package's re-exported ``sql_verbs`` name and reading it here are the same
underlying object.

Body unchanged from the pre-split monolith - see tools/ast_identity_check.py.
"""

import os

from actx_lib import sql_verbs

from .common import SecurityDecision, _unwrap_tokens



# ----------------------------------------------------------------------
# T6: High-Risk SQL Operations (Ask Confirmation) - TK-43
# ----------------------------------------------------------------------

_SQL_GATE_HEADS = frozenset({"psql", "sqlite3", "duckdb"})


def _sql_ask(reason: str) -> SecurityDecision:
    return SecurityDecision(
        decision="ask", reason=reason, category="T6_HIGH_RISK_SQL"
    )


def _check_sql(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    """T6_HIGH_RISK_SQL (TK-43, REQ-03): full SQL payload gating for
    psql/sqlite3/duckdb plus pg_restore.

    - Worst-verb word-boundary scan over the WHOLE chunk (H-F2): the hook
      path normalizes spacing around ``;``/``<``/``>`` in
      _split_into_chunks/_fast_tokenize before this runs, so scanning by
      exact payload tokens alone would be fragile - when a payload token
      is not found, the whole-chunk scan still decides.
    - Payload classification (sql_verbs.sql_payloads - the same extraction
      the rewriter predicate uses): every -c payload (psql/duckdb, incl.
      repeated -c) and the sqlite3 positional SQL must carry an explicit
      RO class; default-deny asks (N-F2a).
    - File-based SQL cannot be scanned -> ask: psql -f/--file,
      sqlite3/duckdb -init, the .read dot-commands (caught by the
      classify-level blacklist) and pg_restore archives (N-F2c).
    - Own try/except -> ask: for SQL heads the outer fail-open returning
      allow would be unacceptable (N-F8).

    Known safe-direction false positives (documented): an argument value
      containing a bare dangerous word as its own token (`psql -d drop`)
      asks, same class as the T6 flag-value FP; a `;` or dangerous word
      inside a SQL string literal asks (worst-statement classification)."""
    try:
        # Substring pre-filter (T5 precedent): non-SQL commands stop at one
        # cheap scan; the gate budget is <1ms (PRD 12).
        if not any(
            h in command for h in ("psql", "sqlite3", "duckdb", "pg_restore")
        ):
            return None
        tokens = _unwrap_tokens(raw_tokens)
        if not tokens:
            return None
        head = os.path.basename(tokens[0])
        if head == "pg_restore":
            return _sql_ask(
                "pg_restore writes a database from an archive file whose SQL cannot be scanned, requiring human confirmation"
            )
        if head not in _SQL_GATE_HEADS:
            return None
        rest = tokens[1:]
        if any(
            tok in sql_verbs.SQL_FILE_FLAGS or tok.startswith("--file=")
            for tok in rest
        ):
            return _sql_ask(
                "SQL from a file (-f/--file/-init) cannot be scanned, requiring human confirmation"
            )
        dangerous = sql_verbs.danger_reason(command)
        if dangerous:
            return _sql_ask(dangerous)
        payloads = sql_verbs.sql_payloads(head, rest)
        if not payloads:
            # Bare REPL / flags-only listing form: nothing to classify (the
            # hang policy owns the interactive case, exit 125).
            return None
        for payload in payloads:
            if sql_verbs.classify_payload(payload) != "ro":
                return _sql_ask(
                    "SQL payload without an explicit read-only class (%r) requires human confirmation (default-deny)"
                    % payload.strip()[:40]
                )
        return None
    except Exception:
        return _sql_ask(
            "SQL gate internal error - requiring human confirmation"
        )
