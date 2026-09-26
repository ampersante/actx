"""TK-60: closed-grammar rewrite engine.

Replaces the former "head allowed, dangerous flag denied by name" model
(open by construction: an unlisted flag was silently admitted) with a
closed one: a command rewrites only if EVERY token after the head matches
an explicit admission rule in `actx_lib.rewrite_spec.HEAD_SPECS` (data,
per plan `2026-09-27-gate-split-allowlist.md` S5.1). A head absent from
HEAD_SPECS, or any token the matching head-spec does not explicitly admit,
means "do not rewrite" - never a fallback to the old predicate-based
admission. This module is the engine only; the specs are pure data in
`rewrite_spec.py`.
"""
import os
import shlex

from actx_lib import cli_families, rewrite_spec, sql_verbs

_FORBIDDEN = set("\n\r\t\0;&&|<>$`(){}#")

# Re-exported for `filters/git_filter.py` (`from actx_lib.rewriter import
# BRANCH_READ_ONLY`); rewrite_spec.py is the single source of the value.
BRANCH_READ_ONLY = rewrite_spec.BRANCH_READ_ONLY

# --- SQL CLIs (TK-43, REQ-06): the ONLY heads with the quote-aware guard ---
_SQL_HEADS = frozenset({"psql", "sqlite3", "duckdb"})


def _quoted_token(tok):
    """True when the token starts AND ends with a quote char (shlex
    posix=False keeps the quotes inside the token)."""
    return len(tok) >= 2 and tok[0] in "'\"" and tok[-1] in "'\""


def _c_payload_tokens(rest):
    """(index, token) of every -c/--command payload token; a missing value
    yields (index, None)."""
    out = []
    i = 0
    n = len(rest)
    while i < n:
        if rest[i] in ("-c", "--command"):
            out.append((i + 1, rest[i + 1] if i + 1 < n else None))
            i += 2
            continue
        i += 1
    return out


def _sql_guard_ok(command):
    """Quote-aware guard for SQL heads (TK-43, wave-2 plan section 3 /
    H-F1/N-F8). Replaces the raw metachar reject for `_SQL_HEADS` ONLY:

    - `shlex.split(command, posix=False)` keeps the quotes in the tokens;
      an unclosed quote raises ValueError -> reject.
    - Every `_FORBIDDEN` metacharacter of the command must sit inside a
      token that starts AND ends with a quote (shell-injected unquoted
      metachars like `psql -c SELECT 1; rm -rf /` reject).
    - The payload must be a SINGLE quoted token after `-c` (psql/duckdb,
      every occurrence) or the last positional at >=2 positionals
      (sqlite3) - else reject.

    Structural only; the SQL class (RO vs dangerous) is decided by the
    per-head spec's `sql_payload` hook below, so guard and hook both must
    pass."""
    try:
        toks = shlex.split(command, posix=False)
    except ValueError:
        return False  # unclosed quote
    if not toks or toks[0] not in _SQL_HEADS:
        return False
    for tok in toks:
        if any(ch in _FORBIDDEN for ch in tok) and not _quoted_token(tok):
            return False
    rest = toks[1:]
    payloads = _c_payload_tokens(rest)
    if payloads:
        return all(tok is not None and _quoted_token(tok) for _, tok in payloads)
    if toks[0] == "sqlite3":
        positionals = [tok for tok in rest if not tok.startswith("-")]
        return len(positionals) >= 2 and _quoted_token(positionals[-1])
    return False


# ---------------------------------------------------------------------
# Named semantic hooks (REQ-06). Each hook wraps an EXISTING function
# (cli_families.gradle_task_class, sql_verbs.sql_payloads/classify_payload)
# verbatim - no logic is duplicated here, only orchestrated.
# ---------------------------------------------------------------------

def _hook_gradle_task_ok(token):
    return cli_families.gradle_task_class(token) == "ro"


# Per-positional-token semantic classifiers (REQ-06): a level declaring one
# of these names has EVERY positional token it encounters (not its
# sub-levels' tokens) checked through the classifier instead of being
# accepted unconditionally. Each wraps an existing function verbatim
# (cli_families.gradle_task_class) or is a tiny, self-contained rule that
# has no separate "existing function" to reuse (cargo's "+toolchain"
# leading-token convention; ls's POSIX non-empty-path rule).
_POSITIONAL_HOOKS = {
    "gradle_task": _hook_gradle_task_ok,
    "cargo_toolchain": lambda tok: tok.startswith("+"),
    "nonempty_positional": lambda tok: tok != "",
}


def _hook_sql_payload_ok(head, argv):
    payloads = sql_verbs.sql_payloads(head, argv)
    if not payloads:
        return False  # bare REPL / no payload: hang_policy owns it, not us
    return all(sql_verbs.classify_payload(p) == "ro" for p in payloads)


# ---------------------------------------------------------------------
# Closed-grammar matcher
# ---------------------------------------------------------------------

def _own_flags(level):
    return (level["bool"], level["value"], level["optional"],
            level["cluster"], level["numeric"])


def _merge_flags(inner, outer):
    """`inner`'s admissions win on key overlap (value/optional domains)."""
    i_bool, i_value, i_optional, i_cluster, i_numeric = inner
    o_bool, o_value, o_optional, o_cluster, o_numeric = outer
    return (
        i_bool | o_bool,
        {**o_value, **i_value},
        {**o_optional, **i_optional},
        i_cluster or o_cluster,
        i_numeric or o_numeric,
    )


def _scanning_eff(level, ancestor_eff):
    """(bool, value, optional, cluster, numeric) admitted while scanning
    THIS level's own tokens - folds in `ancestor_eff` (the accumulated
    flags of every strict ancestor) only when `level["inherit"]` is True
    (pflag/Cobra persistent-flag semantics; git: False; an intermediate
    multi-token verb-path node: False, so no family flag can be interposed
    between the path's own tokens - see `_verb_tree`)."""
    own = _own_flags(level)
    if not level["inherit"] or ancestor_eff is None:
        return own
    return _merge_flags(own, ancestor_eff)


def _child_ancestor_eff(level, ancestor_eff):
    """What gets passed down to a matched verb-child as ITS `ancestor_eff`
    - ALWAYS accumulates this level's own flags, regardless of whether
    this level itself inherited from its own parent: "inherit=False" only
    means "I don't admit my ancestors' flags in MY OWN scanning zone", it
    must not also erase the ancestor chain for further descendants (a
    terminal leaf under a non-inheriting intermediate node still needs the
    family's root-level flags after the whole verb path completes)."""
    own = _own_flags(level)
    if ancestor_eff is None:
        return own
    return _merge_flags(own, ancestor_eff)


def _looks_like_signed_numeric_value(tok):
    """True for a POSIX-style signed numeric value token: an optional
    leading `+`/`-` immediately followed by a digit, then anything (`-1`,
    `+7`, `-1h30m`, `+10M`) - used ONLY to let a required-value flag
    accept a leading-sign numeric next token (`find ... -mtime -1`,
    `-size +10M`) without opening the general "value looks like the next
    flag" ambiguity: no declared flag of any head in this module is
    spelled with a digit immediately after its leading dash, so this can
    never be confused with an actual flag spelling."""
    return len(tok) >= 2 and tok[0] in "+-" and tok[1].isdigit()


def _match_value_flag(tok, next_tok, flag, domain):
    """Required-value flag `flag` against `tok` (+ `next_tok` for the
    separate-token form). Returns tokens-consumed (1 or 2) or None. A
    following token starting with "-" is never accepted as the value,
    EXCEPT a POSIX-style signed numeric token (see
    `_looks_like_signed_numeric_value`)."""
    if tok == flag:
        if next_tok is None:
            return None
        if next_tok.startswith("-") and not _looks_like_signed_numeric_value(next_tok):
            return None
        return 2 if _value_ok(domain, next_tok) else None
    if tok.startswith(flag + "="):
        return 1 if _value_ok(domain, tok[len(flag) + 1:]) else None
    if len(flag) == 2 and flag[0] == "-" and flag[1] != "-" and tok.startswith(flag) and len(tok) > 2:
        # glued short form: -fVALUE
        return 1 if _value_ok(domain, tok[2:]) else None
    return None


def _match_optional_flag(tok, flag, domain):
    """Optional-value flag: glued/`=` form only, or the bare flag with an
    empty value; a following bare token is never consumed."""
    if tok == flag:
        return 1
    if tok.startswith(flag + "="):
        return 1 if _value_ok(domain, tok[len(flag) + 1:]) else None
    if len(flag) == 2 and flag[0] == "-" and flag[1] != "-" and tok.startswith(flag) and len(tok) > 2:
        return 1 if _value_ok(domain, tok[2:]) else None
    return None


def _value_ok(domain, value):
    if domain == "any":
        return True
    if domain == "int":
        return value.lstrip("+-").isdigit()
    return value in domain  # frozenset of allowed literal values


def _cluster_ok(bool_set, body):
    """A cluster of short boolean flags (`-la`): every character, prefixed
    with "-", must be an admitted single-dash boolean flag; any other
    character (unknown, or a value-flag's letter) fails closed."""
    for ch in body:
        if f"-{ch}" not in bool_set:
            return False
    return True


def _match_cluster_with_trailing_value(tok, next_tok, eff):
    """A short-flag cluster (`cluster=True`) whose LAST character is a
    declared single-char value flag, the rest boolean (`-am` == `-a -m`,
    getopt-style clustering where only the final flag in the group may
    take a value). Returns tokens-consumed (2, since the value is always
    the separate next token here) or None. Distinct from `_cluster_ok`
    (all-boolean clusters) and from `_match_value_flag`'s own glued-value
    form (`-mVALUE`, a single flag, not a cluster of several)."""
    bool_set, value_map, _optional_map, cluster, _numeric = eff
    if not cluster or len(tok) <= 2 or tok[1] == "-":
        return None
    body = tok[1:]
    prefix, last = body[:-1], body[-1]
    for ch in prefix:
        if f"-{ch}" not in bool_set:
            return None
    last_flag = f"-{last}"
    domain = value_map.get(last_flag)
    if domain is None:
        return None
    if next_tok is None or (
        next_tok.startswith("-") and not _looks_like_signed_numeric_value(next_tok)
    ):
        return None
    return 2 if _value_ok(domain, next_tok) else None


def _match_flag(tok, eff):
    """One flag token -> tokens-consumed, given as a 1-tuple (consumed,)
    when `tok` alone is the whole match, or None when unmatched. Caller
    supplies the next token separately for required-value flags."""
    bool_set, value_map, optional_map, cluster, numeric = eff
    if tok in bool_set:
        return 1
    if numeric and tok[1:].isdigit():
        return 1
    if cluster and len(tok) > 2 and tok[1] != "-" and _cluster_ok(bool_set, tok[1:]):
        return 1
    for flag, domain in optional_map.items():
        if tok == flag or tok.startswith(flag + "="):
            n = _match_optional_flag(tok, flag, domain)
            if n is not None:
                return n
    return None


def _match_level(level, tokens, ancestor_eff):
    """True when `tokens` (everything after the head, or after the last
    matched verb token) fully satisfies `level`'s grammar. `ancestor_eff`
    is the accumulated (bool, value, optional, cluster, numeric) admission
    of every strict ancestor level, or None at the head."""
    require_any_of = level["require_any_of"]
    if require_any_of and require_any_of.isdisjoint(tokens):
        # Checked against the WHOLE tail (including anything past a `--`
        # boundary this level forwards) so e.g. `cargo fmt -- --check`
        # satisfies fmt's "must carry --check somewhere" requirement the
        # same as the direct `cargo fmt --check` form does.
        return False
    if level["forbid_write_token"] and any(
        tok in ("--fix", "fix", "format") or tok.startswith("--fix")
        for tok in tokens
    ):
        return False
    eff = _scanning_eff(level, ancestor_eff)
    bool_set, value_map, optional_map, cluster, numeric = eff
    verbs = level["verbs"]
    hook = level["hook"]
    i, n = 0, len(tokens)
    positionals = 0
    verb_matched = False
    while i < n:
        tok = tokens[i]
        if tok in level["dashdash_literals"]:
            return _match_after_dashdash(level, tokens[i + 1:])
        if not verb_matched and verbs and tok in verbs:
            verb_matched = True
            return _match_level(verbs[tok], tokens[i + 1:],
                                 _child_ancestor_eff(level, ancestor_eff))
        if tok.startswith("-") and tok != "-":
            consumed = _match_flag(tok, eff)
            if consumed is not None:
                i += consumed
                continue
            next_tok = tokens[i + 1] if i + 1 < n else None
            matched = None
            for flag, domain in value_map.items():
                c = _match_value_flag(tok, next_tok, flag, domain)
                if c is not None:
                    matched = c
                    break
            if matched is None:
                matched = _match_cluster_with_trailing_value(tok, next_tok, eff)
            if matched is None:
                return False
            i += matched
            continue
        # positional (or, for hook-bearing levels, a semantically
        # classified positional - REQ-06, e.g. gradle task tokens)
        classifier = _POSITIONAL_HOOKS.get(hook)
        if classifier is not None and not classifier(tok):
            return False
        cap = level["positional"]
        if cap == "none":
            return False
        if isinstance(cap, tuple) and positionals >= cap[1]:
            return False
        positionals += 1
        i += 1
    if verbs and level["require_verb"] and not verb_matched:
        return False
    return True


def _match_after_dashdash(level, rest):
    mode = level["after_dashdash"]
    if mode == "forbid":
        return False
    if mode == "positional":
        cap = level["positional"]
        if cap == "none":
            return not rest
        if isinstance(cap, tuple):
            return len(rest) <= cap[1]
        return True
    if isinstance(mode, tuple) and mode[0] == "forward":
        forward_spec = rewrite_spec.FORWARD_SPECS[mode[1]]
        return _match_level(forward_spec, rest, None)
    return False


def _match_head(head_spec, argv):
    return _match_level(head_spec, argv, None)


def _sql_head_ok(head, argv):
    """SQL heads (psql/sqlite3/duckdb): the closed flag/positional grammar
    (file flags, admin flags like `-cmd`/`-init`/`-unsafe-testing` are
    closed simply by never being declared) plus the `sql_payload` hook."""
    head_spec = rewrite_spec.HEAD_SPECS.get(head)
    if head_spec is None or not _match_level(head_spec, argv, None):
        return False
    return _hook_sql_payload_ok(head, argv)


def rewrite(command):
    if not command:
        return None
    if command.startswith("actx "):
        return None
    if len(command) > 4096:
        return None
    if any(ch in _FORBIDDEN for ch in command):
        # TK-43: SQL heads swap the raw metachar reject for the
        # quote-aware guard (real SQL almost always carries `;`/`()`);
        # every other head keeps the strict byte-identical guard.
        parts = command.split()
        head = parts[0] if parts else ""
        if head not in _SQL_HEADS:
            return None
        if not _sql_guard_ok(command):
            return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens:
        return None

    argv = tokens[1:]

    # Run-prefixes (`uv run <inner>`, `xcrun simctl <inner>`, REQ-07): the
    # wrapper's OWN flags are validated by cli_families.run_prefix_split
    # (shared with the security gate, not duplicated here); the INNER
    # command is then validated against ITS OWN head-spec - a head without
    # a confirmed spec never rewrites, closing "uv run <anything>". Basename
    # lookup here mirrors run_prefix_split's own internal basename lookup.
    if os.path.basename(tokens[0]) in cli_families.RUN_PREFIXES:
        inner = cli_families.run_prefix_split(tokens)
        if inner is None:
            return None
        inner_argv, _consumed = inner
        inner_head = inner_argv[0]
        inner_spec = rewrite_spec.HEAD_SPECS.get(inner_head)
        if inner_spec is None:
            return None
        if inner_head in _SQL_HEADS:
            if not _sql_head_ok(inner_head, inner_argv[1:]):
                return None
        elif not _match_head(inner_spec, inner_argv[1:]):
            return None
        return "actx " + command

    # Dispatch keyed by the literal head token (no basename normalization),
    # matching the exact-string dispatch table this replaces.
    if tokens[0] in _SQL_HEADS:
        if not _sql_head_ok(tokens[0], argv):
            return None
        return "actx " + command

    head_spec = rewrite_spec.HEAD_SPECS.get(tokens[0])
    if head_spec is None:
        return None
    if not _match_head(head_spec, argv):
        return None
    return "actx " + command
