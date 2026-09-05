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
# rewriter and gate share the set.
SQL_FILE_FLAGS = ("-f", "--file", "-init")


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
    - sqlite3: the same -c forms when present, otherwise the LAST
      positional token when there are >= 2 positionals (db + SQL; the
      first positional is the database file, never classified).

    Connection args (dbname/user for psql, the db file for sqlite3) are
    deliberately not classified: they are not SQL. They are still covered
    by the whole-chunk danger scan on the gate side."""
    payloads = []
    i = 0
    n = len(rest)
    while i < n:
        tok = rest[i]
        if tok in ("-c", "--command"):
            if i + 1 < n:
                payloads.append(rest[i + 1])
            i += 2
            continue
        if tok.startswith("--command="):
            payloads.append(tok.split("=", 1)[1])
        i += 1
    if not payloads and head == "sqlite3":
        positionals = [tok for tok in rest if not tok.startswith("-")]
        if len(positionals) >= 2:
            payloads.append(positionals[-1])
    return payloads
