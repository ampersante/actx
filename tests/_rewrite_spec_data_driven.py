"""Wave 2026-09-27 finding D: mechanical walk of every level of every
`actx_lib.rewrite_spec.HEAD_SPECS` entry, generating one (description,
command, should_rewrite) case per admitted bool/value/optional/numeric/
cluster spelling (positive) plus per unknown-flag/abbreviation/
value-then-dash probe (negative). Not a test module itself (no `test*`
prefix - not collected by `unittest discover`); imported by
`tests/test_rewrite_spec.py`.

Scope, and why: see the module docstring of `tests/test_rewrite_spec.py`
(SQL heads and FORWARD_SPECS are out of scope here, kept separately).
"""
from actx_lib import rewrite_spec

_SKIP_HEADS = frozenset({"psql", "sqlite3", "duckdb"})

# A minimal, distinctive token that cannot collide with any real flag or
# verb spelling in this file - used for every "unknown flag" probe.
_UNKNOWN_FLAG = "--actx-unknown-flag-xyz"


def _sample_value(domain):
    if domain == "any":
        return "x"
    if domain == "int":
        return "1"
    return sorted(domain)[0]  # frozenset of allowed literal values


def _require_any_of_filler(level):
    """A token sequence satisfying `level`'s own `require_any_of`,
    preferring a plain BOOL member (self-sufficient) over a VALUE member
    (needs its own value token too, e.g. xcodebuild's require_any_of mixes
    "-list" (bool) with "-destination" (required-value) - picking the
    alphabetically-first member blindly can pick a value flag and emit it
    bare)."""
    candidates = sorted(level["require_any_of"])
    if not candidates:
        return []
    for tok in candidates:
        if tok in level["bool"]:
            return [tok]
    for tok in candidates:
        if tok in level["value"]:
            return [tok, _sample_value(level["value"][tok])]
    return [candidates[0]]


def _descend_tokens(level, guard=0):
    """A token sequence that, appended after `level`'s own scan, walks
    down through verb dispatch to a level that needs nothing further
    (require_verb False, or no verbs at all) - satisfying `level`'s own
    `require_verb`/`require_any_of` AND every intermediate descendant's,
    recursively. Returns None only on a cycle/depth bug (never expected
    for the finite verb trees in this module)."""
    if guard > 8:
        return None
    if not (level["verbs"] and level["require_verb"]):
        return _require_any_of_filler(level)
    for tok, child in sorted(level["verbs"].items()):
        rest = _descend_tokens(child, guard + 1)
        if rest is not None:
            return [tok] + rest
    return None


def _close_tokens(level):
    """Tokens to append so `level`'s OWN require_verb (if it both has
    verbs and requires one) is satisfied without adding any flag of a
    DIFFERENT level - the closed-grammar analogue of "descend to a leaf
    that accepts zero further tokens"."""
    if level["verbs"] and level["require_verb"]:
        tokens = _descend_tokens(level)
        return tokens if tokens is not None else []
    return []


def _walk(level, prefix, inherited_filler):
    """Yield (prefix_tokens, level, filler) for `level` and every verb
    descendant. `filler` = tokens (from this level's own require_any_of,
    accumulated with every ancestor's) that must appear somewhere in the
    tail for ALL of them to be satisfied - checked against the WHOLE
    remaining tail at every level, per `_match_level`."""
    my_filler = inherited_filler + _require_any_of_filler(level)
    yield prefix, level, my_filler
    verbs = level["verbs"]
    if verbs:
        for tok, child in verbs.items():
            yield from _walk(child, prefix + [tok], my_filler)


def _is_admitted_elsewhere(tok, level):
    """True when `tok` (e.g. an abbreviation candidate) happens to
    already BE a genuinely admitted spelling at this level - a would-be
    negative probe that's actually a true positive by coincidence, not a
    grammar defect (e.g. rg's "--color" truncates to a real different
    flag "--colo"? no - but "--testPathPatterns"[:-1] happens to equal
    the real, separately-admitted "--testPathPattern")."""
    return (tok in level["bool"] or tok in level["value"]
            or tok in level["optional"] or tok in (level["verbs"] or {}))


def _cases_for_level(prefix, level, filler):
    close = _close_tokens(level)
    tail_ok = filler + close  # appended after a PASSING flag/value probe
    verbs = level["verbs"] or {}
    base = list(prefix)
    bool_set = level["bool"]
    value_map = level["value"]
    optional_map = level["optional"]

    def emit(desc, tokens, should_rewrite):
        return (desc, " ".join(tokens), should_rewrite)

    def positive_tail(f):
        # `f` itself dispatches as a verb (checked before flag-matching -
        # see rewriter._match_level) - no extra tokens needed/wanted to
        # separately satisfy this level's OWN require_verb, since the
        # verb match short-circuits that check entirely.
        return filler if f in verbs else tail_ok

    def maybe_abbrev(category, f):
        if not (f.startswith("--") and len(f) > 4):
            return
        abbr = f[:-1]
        if _is_admitted_elsewhere(abbr, level):
            return  # coincides with a genuinely different admitted spelling
        yield emit(f"{' '.join(prefix)} {category}-abbrev {f}",
                   base + [abbr] + tail_ok, False)

    any_own_flag = bool(bool_set or value_map or optional_map or level["numeric"])

    for f in sorted(bool_set):
        yield emit(f"{' '.join(prefix)} bool {f}", base + [f] + positive_tail(f), True)
        yield from maybe_abbrev("bool", f)

    for f, domain in sorted(value_map.items()):
        val = _sample_value(domain)
        yield emit(f"{' '.join(prefix)} value {f}", base + [f, val] + positive_tail(f), True)
        yield emit(f"{' '.join(prefix)} value-then-dash {f}",
                   base + [f, "-x"] + tail_ok, False)
        yield from maybe_abbrev("value", f)

    for f, domain in sorted(optional_map.items()):
        yield emit(f"{' '.join(prefix)} optional-bare {f}",
                   base + [f] + positive_tail(f), True)
        yield from maybe_abbrev("optional", f)

    if level["numeric"]:
        yield emit(f"{' '.join(prefix)} numeric -5", base + ["-5"] + tail_ok, True)

    if level["cluster"]:
        singles = sorted(f for f in bool_set if len(f) == 2 and f[0] == "-" and f[1] != "-")
        if len(singles) >= 2:
            tok = "-" + singles[0][1] + singles[1][1]
            yield emit(f"{' '.join(prefix)} cluster {tok}", base + [tok] + tail_ok, True)

    if any_own_flag:
        yield emit(f"{' '.join(prefix)} unknown-flag",
                   base + [_UNKNOWN_FLAG] + tail_ok, False)


def iter_flag_cases():
    """Yield (description, command_string, should_rewrite) for every
    admitted/rejected spelling at every level of every non-SQL
    HEAD_SPECS entry."""
    for head, root in rewrite_spec.HEAD_SPECS.items():
        if root is None or head in _SKIP_HEADS:
            continue
        for prefix, level, filler in _walk(root, [head], []):
            yield from _cases_for_level(prefix, level, filler)
