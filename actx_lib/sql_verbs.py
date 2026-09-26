"""SQL payload classification data + helpers (TK-43, REQ-03).

Pure data + pure functions, the only import is ``re`` (cli_families
precedent): rewriter and security_gate both read it directly, so the cheap
hook/rewrite import boundary gains no transitive modules.

Classification policy (wave-2 plan section 4 E5.2):

- RO class: a leading statement verb in {SELECT, SHOW, EXPLAIN, VALUES,
  WITH, TABLE, SET} or a safe psql meta (\\d \\dt \\l \\di \\du \\dn \\df
  \\dv \\z \\conninfo). SET is deliberately included with the non-privilege
  reading (H-F15 compromise): `SET search_path` is the mass-harmless
  preamble of every session, and a `-c` payload runs in its own session;
  the privilege forms are rejected by SET_PRIVILEGE_RE first.
- Worst-verb: a dangerous verb ANYWHERE in the payload (word boundary,
  case-insensitive) rejects it - this catches CTE wrappers
  (`WITH x AS (DELETE FROM t) SELECT 1`) and multi-statement strings
  (`SELECT 1; DROP TABLE x`) by their worst statement (N-F14a).
- Metacommand blacklist: psql \\! \\copy \\i \\o \\gexec \\g \\watch \\set
  and the sqlite3/duckdb dot commands .shell .system .read .import .once
  .output .backup execute shells or files -> ask (N-F2b).
- Default-deny (N-F2a): EVERY `;`-separated statement must carry an
  explicit RO class; an unclassified statement asks. Known safe-direction
  false positives (documented): a `;` or a dangerous word inside a string
  literal or comment (`SELECT ';'`, `-- drop later`) asks; PRAGMA / BEGIN
  / RESET are not classified and ask.

``danger_reason`` scans arbitrary text (the security gate's whole-chunk
scan, H-F2); ``sql_payloads`` extracts SQL payload strings from argv
tokens - the single extraction shared by the rewriter predicates and the
gate so the two never drift apart.
"""

import re

RO_STATEMENT_RE = re.compile(
    r"^\s*(?:SELECT|SHOW|EXPLAIN|VALUES|WITH|TABLE|SET)\b", re.IGNORECASE
)

# Safe psql metas (lookahead: `\dt`/`\dt+` match, `\dtx`-style does not).
SAFE_PSQL_META_RE = re.compile(
    r"^\s*\\(?:conninfo|dt|di|du|dn|df|dv|d|z|l)(?![a-zA-Z])"
)

# Worst-verb scan (N-F14a + H-F15: SET is handled by SET_PRIVILEGE_RE).
DANGEROUS_VERB_RE = re.compile(
    r"\b(?:DROP|TRUNCATE|DELETE|UPDATE|INSERT|ALTER|GRANT|REVOKE|CREATE"
    r"|REPLACE|MERGE|COPY|VACUUM|REINDEX|CALL|DO|COMMENT|REFRESH|CLUSTER"
    r"|LOCK)\b",
    re.IGNORECASE,
)

# Privilege escalation via SET (H-F15): `SET search_path` and other
# session-local settings pass; SET ROLE / SET SESSION AUTHORIZATION ask.
SET_PRIVILEGE_RE = re.compile(
    r"\bSET\s+(?:SESSION\s+AUTHORIZATION|ROLE)\b", re.IGNORECASE
)

# psql metacommands that execute shells/files/streams (N-F2b); longest
# alternatives first so `\gexec` wins over `\g`, and the lookahead keeps
# `\i` from matching `\if`/`\ir` (those still ask via default-deny).
PSQL_META_BLACKLIST_RE = re.compile(
    r"\\(?:!|gexec|copy|watch|set|i|o|g)(?![a-zA-Z])"
)

# sqlite3/duckdb dot-commands that execute shells/files (N-F2b).
DOT_META_BLACKLIST_RE = re.compile(
    r"(?:^|[\s;])\.(?:shell|system|read|import|once|output|backup)\b"
)

# File flags of the SQL CLIs: file-based SQL cannot be scanned (N-F2c);
# rewriter and gate share the set. "--init" added (TK-57 REQ-02/REQ-03,
# dual defense with the mode-flag marker mechanism below - E-010: the
# double-dash spelling was missing and rewrote/allowed `sqlite3 --init
# boot.sql db 'SELECT 1'`).
SQL_FILE_FLAGS = ("-f", "--file", "-init", "--init")

# TK-57 REQ-02: mode-altering flags of sqlite3/duckdb - each flips the CLI
# into a non-standard, non-RO mode (archives/appends/writes the database,
# disables safety checks, or runs a startup script) regardless of the
# -c/positional SQL text. Matched by name after stripping 1-2 leading
# dashes (sqlite3/duckdb accept either dash-count for every option) and an
# attached "=value" suffix. sqlite3's -A/--A/-Ax<args> archive-mode family
# is a case-sensitive PREFIX match (`.archive`; distinct from -ascii/
# -append, which start lowercase) since sqlite3 glues archive args onto
# -A (`-Ax a.sar`) - source: sqlite3 3.43.2 --help (local, plan E-003).
# duckdb: confirmed via the official CLI arguments page
# https://duckdb.org/docs/current/clients/cli/arguments.html (fetched
# 2026-09-26) - "-append" ("Append the database to the end of the file")
# and "-unsigned" ("Allow loading of unsigned extensions") are real,
# documented duckdb flags; "-zip"/"-unsafe-testing"/"-nonce" are NOT
# documented for duckdb but are denied defensively too (unconfirmed member
# -> safe default per plan v4 §5.2: denying a flag the CLI doesn't have
# costs nothing, since it can never appear in legitimate duckdb usage).
# "-init" is also covered by SQL_FILE_FLAGS above (dual defense).
_SQL_MODE_FLAG_NAMES = {
    "sqlite3": frozenset({"append", "zip", "unsafe-testing", "nonce", "init"}),
    "duckdb": frozenset({"append", "zip", "unsafe-testing", "nonce", "init",
                          "unsigned"}),
}

# TK-57 REQ-03: value-flags of sqlite3/duckdb that carry no SQL semantics -
# their value is neither a SQL payload nor a positional SQL argument
# (arity = how many separate tokens the flag consumes as VALUE(S) when the
# value is not attached via "="). sqlite3 set: sqlite3 3.43.2 --help
# (local, plan §4). duckdb set: the CLI arguments page above ("-newline
# SEP", "-nullvalue TEXT", "-separator SEP", "-storage-version VER").
# Skipping these prevents their value tokens from being mis-counted as SQL
# positionals (E-004 class: `sqlite3 db 'DROP TABLE t' -separator 'SELECT
# 1'` must classify "DROP TABLE t" as the only positional, not also treat
# the -separator value as a second one).
_SQL_VALUE_FLAG_ARITY = {
    "sqlite3": {
        "newline": 1, "separator": 1, "nullvalue": 1, "vfs": 1,
        "key": 1, "hexkey": 1, "textkey": 1, "maxsize": 1,
        "lookaside": 2, "pagecache": 2,
    },
    "duckdb": {
        "newline": 1, "separator": 1, "nullvalue": 1, "storage-version": 1,
    },
}


def _mode_flag_marker(head, tok):
    """None, or `tok` itself as a non-RO marker payload (classify_payload
    default-denies any string that isn't an explicit RO statement), when
    `tok` is a mode-altering flag of `head` (TK-57 REQ-02). The marker
    forces both the rewriter predicate (all-payloads-RO) and the gate
    (per-payload classify) to the same "not RO" outcome with no separate
    gate edit needed - one extraction, two consumers."""
    if not tok.startswith("-"):
        return None
    stripped = tok[2:] if tok.startswith("--") else tok[1:]
    if head == "sqlite3" and stripped[:1] == "A":
        return tok
    name = stripped.split("=", 1)[0]
    if name in _SQL_MODE_FLAG_NAMES.get(head, ()):
        return tok
    return None


def _value_flag_skip(head, tok):
    """Number of rest[] tokens (this flag token plus any separate value
    token(s)) to skip when `tok` is a non-SQL value-flag of `head` (TK-57
    REQ-03) - 0 when `tok` is not such a flag. Handles any dash-count and
    the attached `-x=value`/`--x=value` single-token form (0 extra
    tokens beyond this one)."""
    if not tok.startswith("-"):
        return 0
    body = tok[2:] if tok.startswith("--") else tok[1:]
    name, sep, _value = body.partition("=")
    arity = _SQL_VALUE_FLAG_ARITY.get(head, {}).get(name)
    if arity is None:
        return 0
    return 1 if sep else 1 + arity


def danger_reason(text):
    """Reason string when free text carries a dangerous SQL construct
    (dangerous verb, privilege SET, blacklisted metacommand); None when
    clean. Word-boundary based, so the security gate can run it over a
    whole normalized chunk (H-F2)."""
    if not isinstance(text, str) or not text:
        return None
    if PSQL_META_BLACKLIST_RE.search(text):
        return "psql metacommand (\\!, \\copy, \\i, \\o, \\gexec, \\g, \\watch, \\set) executes shells or files"
    if DOT_META_BLACKLIST_RE.search(text):
        return "dot command (.shell/.system/.read/.import/.once/.output/.backup) executes shells or files"
    if SET_PRIVILEGE_RE.search(text):
        return "SET ROLE / SET SESSION AUTHORIZATION escalates privileges"
    match = DANGEROUS_VERB_RE.search(text)
    if match:
        return "dangerous SQL verb '%s' requires human confirmation" % match.group(0).upper()
    return None


def classify_payload(payload):
    """Classify one SQL payload string: "ro" or "ask" (default-deny).

    Order: metacommand blacklist and privilege SET over the whole payload,
    then the worst-verb scan, then every `;`-separated statement must carry
    an explicit RO class (leading verb or safe psql meta)."""
    if not isinstance(payload, str) or not payload.strip():
        return "ask"
    if danger_reason(payload):
        return "ask"
    for statement in payload.split(";"):
        if not statement.strip():
            continue
        if not (
            RO_STATEMENT_RE.match(statement)
            or SAFE_PSQL_META_RE.match(statement)
        ):
            return "ask"
    return "ro"


def sql_payloads(head, rest):
    """SQL payload strings of an exec-array tail (head excluded).

    - psql / duckdb: the token after every ``-c``/``--command`` flag plus
      ``--command=`` forms (psql supports repeated -c; every occurrence is
      a payload - `psql -c "SELECT 1" -c "DROP x"` classifies by both).
    - sqlite3 / duckdb: the same -c/-cmd forms when present, PLUS every
      positional token after the first (db file) when there are >= 2
      positionals (TK-57 REQ-02/REQ-03) - not just the last: sqlite3 and
      duckdb both execute EVERY positional after the db file as its own
      SQL statement in order (confirmed for sqlite3 by E-004: `sqlite3
      t.db 'DROP TABLE t' -separator 'SELECT 1'` executed the DROP even
      though the prior single-last-positional rule only classified the
      trailing 'SELECT 1'; confirmed for duckdb by the official CLI docs
      https://duckdb.org/docs/current/clients/cli/overview.html, whose own
      non-interactive example `duckdb :memory: "SELECT 42"` runs a second
      positional as SQL). Value-flag tokens without SQL semantics
      (_value_flag_skip) are consumed with their value(s) first so they
      are never miscounted as a positional - REQ-03: "значения прочих
      value-флагов не считаются ни payload, ни позиционными".
    - Mode-altering flags (_mode_flag_marker, REQ-02) inject the flag
      token itself as a non-RO marker payload, forcing both the rewriter
      (all-RO required) and the gate (default-deny) to refuse regardless
      of what SQL text follows.

    Connection args (dbname/user for psql, the db file for sqlite3/
    duckdb) are deliberately not classified: they are not SQL. They are
    still covered by the whole-chunk danger scan on the gate side."""
    payloads = []
    positional_idx = []
    i = 0
    n = len(rest)
    while i < n:
        tok = rest[i]
        # `-cmd` (sqlite3; duckdb mirrors) takes a COMMAND payload run
        # before stdin — meta-commands (.shell/.output/.read) inside it
        # must reach the classifier like any -c payload.
        if tok in ("-c", "--command", "-cmd"):
            if i + 1 < n:
                payloads.append(rest[i + 1])
            i += 2
            continue
        if tok.startswith("--command="):
            payloads.append(tok.split("=", 1)[1])
            i += 1
            continue
        marker = _mode_flag_marker(head, tok)
        if marker is not None:
            payloads.append(marker)
            i += 1
            continue
        skip = _value_flag_skip(head, tok)
        if skip:
            i += skip
            continue
        if not tok.startswith("-"):
            positional_idx.append(i)
        i += 1
    if head in ("sqlite3", "duckdb") and len(positional_idx) >= 2:
        # Every positional after the first (the db file) is a SQL
        # statement, classified alongside -c/-cmd/marker payloads, not
        # only in their absence.
        for idx in positional_idx[1:]:
            payloads.append(rest[idx])
    return payloads
