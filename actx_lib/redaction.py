"""Secret value masking (TK-61): the single masking mechanism for the screen,
the tee file and tracking (`secret_bearing`).

A secret is found by data rows: known token formats (`_FORMAT_ROWS`) and
values that follow a secret-named key (`_SECRET_PATTERNS` + the closed
exclusions (a)-(d)). Only the value span is replaced by `MASK`; the line,
the key, quotes and delimiters outside the span stay byte-identical.
Idempotent: masking masked text changes nothing. A masking exception
never yields raw text (withhold_text: line-drop plus a marker line).

Value forms (spans):
1. Quoted key, JSON-style (`"k": v`, `'k': v`, escaped at any level:
   `\\"k\\":\\"v\\"`, `\\\\\\"k\\\\\\": ...` - a document embedded n times in
   JSON strings writes its `"` as 2^n-1 backslashes + `"`): a string ->
   its content; a number/true/false/null -> `"‹masked›"`; an object/array
   -> the whole container (bracket scan) -> `"‹masked›"`; any other
   unquoted value -> the run up to whitespace, `, ) ] }` or a quote (the
   enclosing string's end). A value never crosses a delimiter of an
   enclosing level. `"‹masked›"` is quoted at the key's level
   (`\\"‹masked›\\"` at level 1, ...), `'‹masked›'` for a '...' key inside
   an open "..." string, so every enclosing JSON level stays valid.
   Unquoted runs keep a backslash pair as one unit. JSON whitespace (LF,
   CR included) may surround the `:`; the key of any length is tested
   with its \\uXXXX escapes decoded.
2. Unquoted key, quoted value (`k = "v"`, `k: 'v'`, `--k "v"`) -> content.
3. Unquoted key, `=`, unquoted value -> the run up to whitespace or
   `; , & ) ] } " '`; a value starting with `{`/`[` takes the bracket scan
   first, then continues with that run. A string-prefixed literal
   (`b'v'`, `rb"v"`; also in forms 1 and 5) -> its quoted content, the
   prefix stays.
4. Unquoted key, `:`, unquoted value -> the rest of the line up to
   whitespace + `#`, trailing whitespace excluded (inside an open "..."
   string on the line, up to its closing quote).
5. Flags (`--k v`, `--k=v`) -> the next token, up to whitespace or a quote.
No value exemptions (numbers, booleans, null, references, identifiers are
masked); no length floor. Known gaps: YAML block scalars, block mappings
and other multi-line values (only the PEM body is covered).
"""

import functools
import heapq
import re

MASK = "‹masked›"

# Secret-named key inventory: the pre-TK-61 baseline list plus passwd/pwd.
# A key is secret-named when its lowercased form with `_ - .` removed
# contains an entry with `_` removed (baseline substring rule, widened by
# separator removal). data_filter column masking reads this tuple too.
_SECRET_PATTERNS = (
    "secret",
    "token",
    "password",
    "accesskey",
    "credential",
    "aws_access_key_id",
    "aws_secret_access_key",
    "api_key",
    "apikey",
    "private_key",
    "secret_key",
    "client_secret",
    "access_key",
    "signing_key",
    "passphrase",
    "passwd",
    "pwd",
)

# Closed exclusion list (plan TK-61 §3), each rule with test rows.
# (a) the whole key is a tokenizer term.
_WHOLE_KEY_EXCLUSIONS = frozenset(
    ("tokenizer", "tokenizers", "tokenize", "detokenize", "detokenizer")
)
# (b) the last segment is a metadata suffix (`url` deliberately absent).
_METADATA_SUFFIXES = frozenset(
    (
        "count", "type", "kind", "name", "file", "path", "dir", "ttl",
        "timeout", "expiry", "expires", "len", "length", "size", "limit",
    )
)
# (c) usage counters: plural `tokens` segment + one of these first segments.
_USAGE_QUALIFIERS = frozenset(
    (
        "max", "min", "n", "num", "total", "input", "output", "prompt",
        "completion", "cached", "cache", "reasoning", "used", "remaining",
    )
)
# (d) pagination cursors, any spelling (compared separator-free, lowercase).
_CURSOR_KEYS = frozenset(
    ("nexttoken", "nextpagetoken", "pagetoken", "continuationtoken")
)

# Known token formats: (name, pattern, needles, positive example, negative
# example, source). The span is group "v" when present, else the whole
# match. needles: lowercase literals, one of which every match contains -
# the pattern runs only when a needle occurs in the lowercased text (speed).
_FORMAT_ROWS = (
    (
        "github",
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})",
        ("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
        "ghp_" + "a1B2c3D4e5" * 3 + "a1B2c3",
        "ghp_short",
        "GitHub token formats (ghp_/gho_/ghu_/ghs_/ghr_, github_pat_)",
    ),
    (
        "openai-anthropic",
        r"\bsk-(?=[A-Za-z_-]*[0-9])[A-Za-z0-9_-]{20,}",
        ("sk-",),
        "sk-ant-api03-abcdefghij0123456789",
        "sk-learn-is-a-library",
        "OpenAI sk-/sk-proj-, Anthropic sk-ant- keys",
    ),
    (
        "aws-access-key-id",
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        ("akia", "asia"),
        "AKIAIOSFODNN7EXAMPLE",
        "AKIASHORT",
        "AWS access key id (long-term AKIA, temporary ASIA)",
    ),
    (
        "slack",
        r"\bxox(?:[abprsce]|e\.xox[abprsce])-[A-Za-z0-9-]{10,}",
        ("xox",),
        "xoxb-1234567890-abcdefghij",
        "xoxo-hugs-and-kisses",
        "Slack tokens: xoxa/xoxb/xoxp/xoxr/xoxs, client xoxc, refresh xoxe, "
        "rotating xoxe.xox?-",
    ),
    (
        "stripe",
        r"\b(?:sk|rk)_live_[A-Za-z0-9]{10,}",
        ("_live_",),
        "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "Stripe live secret/restricted keys",
    ),
    (
        "google-api-key",
        r"\bAIza[0-9A-Za-z_-]{35}",
        ("aiza",),
        "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6q",
        "AIzaShort",
        "Google API key",
    ),
    (
        "npm",
        r"\bnpm_[A-Za-z0-9]{36}\b",
        ("npm_",),
        "npm_" + "a1B2c3D4e5" * 3 + "a1B2c3",
        "npm_install",
        "npm access token",
    ),
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
        ("eyj",),
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
        "eyJhbGciOiJIUzI1NiJ9",
        "JSON Web Token (header.payload.signature)",
    ),
    (
        "pem-private-key",
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?P<v>.*?)"
        r"(?=-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)",
        ("private key-----",),
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        "PEM private key body (RFC 7468)",
    ),
    (
        "url-userinfo",
        r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/:@'\"]*:(?P<v>[^\s/@'\"]+)@",
        ("://",),
        "postgres://app:pa55w0rd@db:5432/app",
        "https://host:8080/path",
        "URL userinfo password (RFC 3986 scheme://user:pass@host)",
    ),
    (
        "authorization-header",
        r"(?i)\bauthorization[\"']?[ \t]*[:=][ \t]*[\"']?(?:bearer|basic|token)[ \t]+"
        r"(?P<v>[^\s\"',;\\]+)",
        ("authorization",),
        "Authorization: Bearer abc.def-123",
        "Authorization: required",
        "HTTP Authorization header (RFC 9110 11.6.2); GitHub `token` scheme",
    ),
)

_FORMAT_RES = tuple(re.compile(row[1], re.S) for row in _FORMAT_ROWS)

_INVENTORY = tuple(sorted({p.replace("_", "") for p in _SECRET_PATTERNS}))
# Candidate trigger: the minimal inventory entries (no other entry inside
# them), letters optionally separated by `_ - .`. A hit only starts the
# key evaluation; the decision is _is_secret_key on the whole key.
_MINIMAL = tuple(
    e for e in _INVENTORY if not any(f != e and f in e for f in _INVENTORY)
)
_CANDIDATE_PATTERN = "|".join(
    "[_.-]*".join(re.escape(c) for c in e) for e in _MINIMAL
)
# Run on the lowercased text when lowering keeps every index (the common
# case, ~10x faster than IGNORECASE); otherwise IGNORECASE on the text.
_CANDIDATE_RE = re.compile(_CANDIDATE_PATTERN)
_CANDIDATE_RE_I = re.compile(_CANDIDATE_PATTERN, re.I)

_KEY_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
)
_SEG_SPLIT_RE = re.compile(r"[_.-]+")
_CAMEL_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_JSON_LITERAL_RE = re.compile(
    r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null"
)
_COMMENT_RE = re.compile(r"[ \t]#")
# A 1-2 letter string prefix (b'', u'', f'', r'', rb'', ...) before a quote.
_STR_PREFIX_RE = re.compile(r"[bBuUfFrR]{1,2}(?=\\*[\"'])")
# \uXXXX at any escape level (`\u`, `\\u`): decoded in quoted key text.
_U_ESCAPE_RE = re.compile(r"\\+u([0-9a-fA-F]{4})")
# A \uXXXX that can spell part of a key name: an ASCII letter, `_ - .`, or
# KELVIN SIGN (lowercases to `k`). Other escapes (e.g. ensure_ascii text)
# cannot turn a key into an inventory word, so they start no evaluation.
_U_KEY_LETTER_RE = re.compile(
    r"\\u(?:00(?:4[1-9A-Fa-f]|5[0-9AaFf]|6[1-9A-Fa-f]|7[0-9Aa]|2[DdEe])|212[Aa])"
)
_HSPACE = " \t"
_JSON_WS = " \t\r\n"
_TRAILING_SPACE = " \t\r"
_FORM3_STOP = frozenset(" \t\r\n\f\v;,&)]}\"'")
_FORM1_STOP = frozenset(" \t\r\n\f\v,)]}\"'")
_FLAG_STOP = frozenset(" \t\r\n\f\v\"'")


def _normalize(key):
    return key.lower().replace("_", "").replace("-", "").replace(".", "")


def _segments(key):
    """Key segments on `_ - .` and camelCase, lowercased. A key with any
    other character is one unsplit segment (exclusions (b)/(c) then never
    apply to it)."""
    if any(c not in _KEY_CHARS for c in key):
        return [_normalize(key)]
    segs = []
    for part in _SEG_SPLIT_RE.split(key):
        segs.extend(s.lower() for s in _CAMEL_RE.findall(part))
    return segs


def _excluded(key, norm):
    if norm in _WHOLE_KEY_EXCLUSIONS:  # (a)
        return True
    segs = _segments(key)
    if segs and segs[-1] in _METADATA_SUFFIXES and norm not in _INVENTORY:  # (b)
        return True
    if "tokens" in segs and segs[0] in _USAGE_QUALIFIERS:  # (c)
        rest = "".join(s for s in segs if s != "tokens")
        if not any(p in rest for p in _INVENTORY):
            return True
    return norm in _CURSOR_KEYS  # (d)


@functools.lru_cache(maxsize=4096)
def _is_secret_key(key):
    norm = _normalize(key)
    if not any(p in norm for p in _INVENTORY):
        return False
    return not _excluded(key, norm)


# --- scanners --------------------------------------------------------------


def _eol(text, i):
    end = text.find("\n", i)
    return len(text) if end < 0 else end


def _rstrip_end(text, start, end):
    while end > start and text[end - 1] in _TRAILING_SPACE:
        end -= 1
    return end


# String bodies: any character but the quote and a backslash (and a line
# break with stop_eol); a backslash escapes the next character.
_STRING_BODY_RES = {
    (quote, stop_eol): re.compile(
        r"(?:[^%s\\%s]|\\.)*" % (quote, "\n" if stop_eol else ""), re.S
    )
    for quote in "\"'"
    for stop_eol in (False, True)
}


def _string_end(text, i, quote, stop_eol):
    """Index of the unescaped closing `quote` for a string whose content
    starts at i; None when absent (on this line when stop_eol)."""
    end = _STRING_BODY_RES[quote, stop_eol].match(text, i).end()
    return end if text[end:end + 1] == quote else None


# --- escape levels ---------------------------------------------------------
# A document embedded n times in JSON strings has its `"` written as 2^n-1
# backslashes + `"`, a literal backslash as 2^n backslashes. So the level of
# a `"` after a run of r backslashes is the number of trailing 1 bits of r
# (0: `"`, 1: `\"`, 2: `\\\"`, 5 = 0b101: `\"` after one literal `\\`); a
# position inside d enclosing strings is at depth d.

# A quote or raw line break with the whole backslash run before it (the
# lookbehind keeps a match from starting inside a run: linear scan).
_TOKEN_RE = re.compile(r"(?<!\\)(\\*+)([\"'\n])")
_DQ_TOKEN_RE = re.compile(r'(?<!\\)(\\*+)"')
_BACKSLASHES_RE = re.compile(r"\\*")
_ESCAPED_BREAKS_RE = re.compile(r"(?:\\+[nrt])+")


def _level(run):
    """Escape level of a `"` after `run` backslashes (trailing 1 bits)."""
    return ((run + 1) & ~run).bit_length() - 1


def _delimiter_start(quote_pos, level):
    """First byte of a level-`level` `"` delimiter ending at quote_pos."""
    return quote_pos - ((1 << level) - 1)


def _run_before(text, p):
    i = p
    while i > 0 and text[i - 1] == "\\":
        i -= 1
    return p - i


def _deep_string_end(text, i, quote, depth):
    """End of a string whose content starts at i: a `"` string of level
    `depth` closes at the next `"` of that level (deeper ones are content);
    a `'` string at depth `depth` closes at the next `'` not escaped at that
    depth; quote None: no own closing quote. A `"` of a shallower level (an
    enclosing string ends), a raw line break (depth >= 1) or the end of text
    is the boundary. Returns (end, closed): end is the first byte of the
    closing or boundary delimiter, so a span [i, end) never cuts one."""
    for m in _TOKEN_RE.finditer(text, i):
        run = len(m.group(1))
        p = m.end() - 1
        ch = m.group(2)
        if ch == '"':
            level = _level(run)
            if quote == '"' and level == depth:
                return _delimiter_start(p, level), True
            if level < depth:
                return _delimiter_start(p, level), False
        elif ch == "'":
            if quote == "'" and not (run >> depth) & 1:
                return p, True
        elif depth:
            return m.start(), False
    return len(text), False


class _Depth:
    """Depth (open "..." strings, at any escape level) at a position, from
    its line start: a `"` of level L opens a string when L equals the
    depth and closes the strings down to L when L is lower. Queries at
    non-decreasing positions scan each byte once."""

    def __init__(self, text):
        self.text = text
        self.pos = 0
        self.depth = 0

    def at(self, pos):
        text = self.text
        if pos < self.pos:
            start, depth = text.rfind("\n", 0, pos) + 1, 0
        else:
            start, depth = self.pos, self.depth
            line = text.rfind("\n", start, pos)
            if line >= 0:
                start, depth = line + 1, 0
        for m in _DQ_TOKEN_RE.finditer(text, start, pos):
            level = _level(len(m.group(1)))
            if level == depth:
                depth += 1
            elif level < depth:
                depth = level
        self.pos, self.depth = pos, depth
        return depth


class _Scan:
    """Per-text scan state for _key_spans. Hits arrive in text order and
    many can share one unbounded region (a long line, an unclosed string,
    run or container), so a forward scan's result is reused for a later
    start inside the scanned range at the same parse state: a start not
    just after a backslash (which could escape it or sit inside a quote's
    run). Every result equals a fresh scan; each region is scanned once.
    Containers are resolved after the hit loop, when every container start
    is known (_bracket_end records only those)."""

    def __init__(self, text):
        self.text = text
        self.depth_at = _Depth(text).at
        self._eol = (0, -1)
        self._comment = (0, -1, None)  # (from, eol, match start or None)
        self._deep = {}  # (quote, depth) -> (from, end, closed)
        self._run = {}  # stop set -> (from, end)
        self._containers = []  # (span index, v, depth, mask, tail stop)

    def _reusable(self, lo, i, hi):
        return lo <= i <= hi and (i == lo or self.text[i - 1] != "\\")

    def eol(self, i):
        lo, hi = self._eol
        if not lo <= i <= hi:
            hi = _eol(self.text, i)
            self._eol = (i, hi)
        return hi

    def comment(self, i, eol):
        """Start of the first ` #`/`\\t#` in [i, eol), or None."""
        lo, last_eol, found = self._comment
        if last_eol == eol and lo <= i and (found is None or i <= found):
            return found
        match = _COMMENT_RE.search(self.text, i, eol)
        found = None if match is None else match.start()
        self._comment = (i, eol, found)
        return found

    def deep_end(self, i, quote, depth):
        lo, end, closed = self._deep.get((quote, depth), (0, -1, False))
        if not self._reusable(lo, i, end):
            end, closed = _deep_string_end(self.text, i, quote, depth)
            self._deep[quote, depth] = (i, end, closed)
        return end, closed

    def run_end(self, i, stop):
        lo, end = self._run.get(stop, (0, -1))
        if not self._reusable(lo, i, end):
            end = _run_end(self.text, i, stop)
            self._run[stop] = (i, end)
        return end

    def container(self, v, depth, mask, tail=None):
        """Placeholder span for the container opening at v (its end is
        set by resolve); tail: a run stop set continuing after it."""
        self._containers.append((v, depth, mask, tail))
        return (v, None, mask, len(self._containers) - 1)

    def resolve(self, spans):
        if not self._containers:
            return spans
        wanted = {}
        for v, depth, _, _ in self._containers:
            wanted.setdefault(depth, set()).add(v)
        memo = {}
        ends = []
        for v, depth, _, tail in self._containers:
            end = _bracket_end(self.text, v, depth, memo, wanted[depth])
            if tail is not None:
                end = self.run_end(end, tail)
            ends.append(end)
        return [
            span if span[1] is not None else (span[0], ends[span[3]], span[2])
            for span in spans
        ]


def _bracket_end(text, i, depth, memo=None, wanted=()):
    """End (exclusive) of the container opening at text[i], at escape depth
    `depth`: one nesting counter for `{[` / `]}` regardless of kind; strings
    of this depth ("..." at its level, '...') are skipped, a backslash
    escapes the next character; crosses lines at depth 0 (fail closed to
    end of text); at depth >= 1 an enclosing delimiter or a raw line break
    ends it (fail closed to that boundary, outer levels intact).

    memo {(depth, opener): (end, closed)}: an opener in `wanted` that this
    scan reaches outside a string has the same end from there (its
    matching closer, or this scan's end when it stays open), so it is
    recorded; a known opener reached outside a string is jumped over
    (closed: balanced) or ends this scan (open: this scan never closes
    either)."""
    if memo is not None and (depth, i) in memo:
        return memo[depth, i][0]
    n = len(text)
    nest = 0
    pending = []  # (wanted opener, its nest) still open
    end = n
    while i < n:
        ch = text[i]
        if ch == "\\" or ch == '"':
            j = _BACKSLASHES_RE.match(text, i).end()
            run = j - i
            if text[j:j + 1] == '"':
                level = _level(run)
                if level < depth:
                    end = _delimiter_start(j, level)
                    break
                if level > depth:
                    i = j + 1  # deeper quote: content
                    continue
                if level == 0:
                    close = _string_end(text, j + 1, '"', False)
                    if close is None:
                        break
                    i = close + 1
                    continue
                end, closed = _deep_string_end(text, j + 1, '"', level)
                if not closed:
                    break
                i = end + (1 << level)
                end = n
                continue
            i = j + 1 if run % 2 else j  # an odd run escapes the next char
            continue
        if ch == "'":
            if depth == 0:
                close = _string_end(text, i + 1, "'", False)
                if close is None:
                    break
                i = close + 1
                continue
            end, closed = _deep_string_end(text, i + 1, "'", depth)
            if not closed:
                break
            i = end + 1
            end = n
            continue
        if ch == "\n" and depth:
            end = i
            break
        if ch in "{[":
            if nest and memo is not None and (depth, i) in memo:
                known, closed = memo[depth, i]
                if closed:
                    i = known
                    continue
                end = known
                break
            nest += 1
            if i in wanted:
                pending.append((i, nest))
        elif ch in "}]":
            if pending and pending[-1][1] == nest:
                memo[depth, pending.pop()[0]] = (i + 1, True)
            nest -= 1
            if nest <= 0:
                return i + 1
        i += 1
    if memo is not None:
        for opener, _ in pending:
            memo[depth, opener] = (end, False)
    return end


def _run_end(text, i, stop):
    """End of an unquoted value run. A backslash run is one unit: an odd run
    escapes the next character; before a quote, a line break or the end of
    text the run ends the value, minus the backslashes that belong to that
    quote's delimiter at its escape level (so `\\\\` of a value stays inside
    it and no delimiter of any level is cut)."""
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in stop:
            break
        if ch == "\\":
            j = _BACKSLASHES_RE.match(text, i).end()
            if text[j:j + 1] in ("", "\"", "'", "\r", "\n"):
                return _delimiter_start(j, _level(j - i))
            i = j + 1 if (j - i) % 2 else j
            continue
        i += 1
    return i


# --- value spans -----------------------------------------------------------


def _quoted_value(text, v, depth):
    """Span of a quoted value starting at v (`"` of any escape level, `'`)
    for a key at escape depth `depth`; unclosed -> to the end of its line or
    enclosing string. None when v starts no quoted value; () when it is
    empty or v is an enclosing string's closing delimiter (no value)."""
    run = _BACKSLASHES_RE.match(text, v).end() - v
    ch = text[v + run:v + run + 1]
    if ch == '"':
        level = _level(run)
        if run != (1 << level) - 1:
            return None  # literal backslashes first: not a quoted value
        if level < depth:
            return ()
        start = v + run + 1
        if level == 0:
            close = _string_end(text, start, '"', True)
            end = _eol(text, start) if close is None else close
            closed = close is not None
        else:
            end, closed = _deep_string_end(text, start, '"', level)
    elif ch == "'" and run == 0:
        start = v + 1
        if depth == 0:
            close = _string_end(text, start, "'", True)
            end = _eol(text, start) if close is None else close
            closed = close is not None
        else:
            end, closed = _deep_string_end(text, start, "'", depth)
    else:
        return None
    if not closed:
        end = _rstrip_end(text, start, end)
    return (start, end, MASK) if end > start else ()


def _prefixed_value(text, v, depth):
    """A string-prefixed literal (`b'v'`, `rb"v"`, `f\\"v\\"`): the span of
    its quoted content (the prefix stays); None when v starts no such
    literal."""
    prefix = _STR_PREFIX_RE.match(text, v)
    if prefix is None:
        return None
    return _quoted_value(text, prefix.end(), depth)


def _form1_value(text, v, qmask, depth, scan):
    """Value after a quoted key (JSON-style) at escape depth `depth`; qmask
    replaces literals and containers, quoted at the key's level."""
    quoted = _quoted_value(text, v, depth)
    if quoted is None:
        quoted = _prefixed_value(text, v, depth)
    if quoted is not None:
        return quoted or None
    if text[v] in "{[":
        return scan.container(v, depth, qmask)
    end = scan.run_end(v, _FORM1_STOP)
    if end == v:
        return None
    literal = _JSON_LITERAL_RE.fullmatch(text, v, end) is not None
    return (v, end, qmask if literal else MASK)


def _form4_value(text, v, sep_end, depth, scan):
    eol = scan.eol(v)
    if text[v] == "#" and v > sep_end:
        return None  # `k: #...` is a comment
    end = eol
    comment = scan.comment(v, eol)
    if comment is not None:
        end = comment
    if depth:  # inside an enclosing string: up to its end
        end = min(end, scan.deep_end(v, None, depth)[0])
    end = _rstrip_end(text, v, end)
    return (v, end, MASK) if end > v else None


def _skip_hspace(text, i):
    n = len(text)
    while i < n and text[i] in _HSPACE:
        i += 1
    return i


def _skip_json_ws(text, i):
    """Skip JSON whitespace (space, tab, LF, CR) and its `\\n`, `\\r`, `\\t`
    escapes at any escape level (the same document embedded in strings or
    printed as a repr)."""
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in _JSON_WS:
            i += 1
            continue
        if ch == "\\":
            escapes = _ESCAPED_BREAKS_RE.match(text, i)
            if escapes is not None:
                i = escapes.end()
                continue
        break
    return i


def _separator(text, i, allow_colon=True):
    """(kind, end) of a `=`/`==`/`=>`/`:` separator after optional blanks."""
    j = _skip_hspace(text, i)
    ch = text[j:j + 1]
    if ch == "=":
        return "=", j + (2 if text[j + 1:j + 2] in ("=", ">") else 1)
    if ch == ":" and allow_colon and text[j + 1:j + 2] != ":":
        return ":", j + 1
    return None, j


def _decode_key(key):
    """Quoted key text with its \\uXXXX escapes decoded (any escape level),
    so an escaped spelling meets the same secret-name test."""
    if "u" not in key or "\\" not in key:
        return key
    return _U_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), key)


def _quoted_key_span(text, start, he, scan):
    """Value span for a quoted key whose text starts at `start` (after the
    nearest quote before the hit) and must contain the hit end `he`; False
    when there is no such quoted key; None when there is but nothing to
    mask. A "..." key of escape level k sits at depth k; a '...' key at
    the depth of its position (scan.depth_at). JSON whitespace (LF, CR and
    their escapes included) may surround the `:`."""
    quote = text[start - 1]
    if quote == '"':
        depth = _level(_run_before(text, start - 1))
    else:
        depth = scan.depth_at(start - 1)
    if depth == 0:
        close = _string_end(text, start, quote, True)
    else:
        close, closed = _deep_string_end(text, start, quote, depth)
        if not closed:
            close = None
    if close is None or close < he:
        return False
    close_end = close + (1 << depth if quote == '"' else 1)
    kind, sep_end = _separator(text, close_end)
    if kind is None:
        if text[sep_end:sep_end + 1] not in ("\r", "\n", "\\"):
            return False  # no line break before a `:` (also: end of text)
        j = _skip_json_ws(text, sep_end)
        if text[j:j + 1] != ":" or text[j + 1:j + 2] == ":":
            return False
        sep_end = j + 1
    if not _is_secret_key(_decode_key(text[start:close])):
        return None
    v = _skip_json_ws(text, sep_end)
    if v >= len(text):
        return None
    if quote == '"':
        delimiter = "\\" * ((1 << depth) - 1) + '"'  # the key's own level
        qmask = delimiter + MASK + delimiter
    elif depth:
        qmask = "'%s'" % MASK  # a `"` would end an enclosing string
    else:
        qmask = '"%s"' % MASK
    return _form1_value(text, v, qmask, depth, scan)


def _unquoted_key_span(text, s, e, scan):
    raw = text[s:e]
    key = raw.lstrip("-")
    dashes = len(raw) - len(key)
    flag = 1 <= dashes <= 2
    if not key or not _is_secret_key(key):
        return None
    kind, sep_end = _separator(text, e)
    if kind is None:
        if not (flag and sep_end > e):
            return None
        kind = " "
    v = _skip_hspace(text, sep_end)
    n = len(text)
    if v >= n or text[v] in "\r\n":
        return None
    depth = scan.depth_at(s)
    quoted = _quoted_value(text, v, depth)
    if quoted is None and kind != ":":
        quoted = _prefixed_value(text, v, depth)  # forms 3/5: b'v', rb"v"
    if quoted is not None:  # form 2
        return quoted or None
    if flag:  # form 5
        end = scan.run_end(v, _FLAG_STOP)
    elif kind == ":":  # form 4
        return _form4_value(text, v, sep_end, depth, scan)
    elif text[v] in "{[":  # form 3 container (and the run after it)
        return scan.container(v, depth, MASK, _FORM3_STOP)
    else:  # form 3
        end = scan.run_end(v, _FORM3_STOP)
    return (v, end, MASK) if end > v else None


def _hits(text, lowered):
    """(start, end, escape_only) in text order: inventory candidates, plus
    every key-letter `\\uXXXX` (a quoted key may spell an inventory word
    with escapes)."""
    if len(lowered) == len(text):
        candidates = _CANDIDATE_RE.finditer(lowered)
    else:
        candidates = _CANDIDATE_RE_I.finditer(text)
    hits = (m.span() + (False,) for m in candidates)
    if "\\u" not in text:
        return hits
    escapes = ((m.start(), m.end(), True) for m in _U_KEY_LETTER_RE.finditer(text))
    return heapq.merge(hits, escapes)


def _key_spans(text, lowered):
    """Hits arrive in text order, so the nearest quote/newline before a hit
    is found incrementally (each byte scanned once) and each quoted key and
    each unquoted key run is evaluated once: linear in the text, whatever
    the key length."""
    spans = []
    seen_quoted = set()
    quoted_by_start = {}
    delim = -1  # nearest `"`, `'` or newline before `scanned`
    scanned = 0
    run_end = 0  # end of the last unquoted key run evaluated
    scan = _Scan(text)
    n = len(text)
    for hs, he, escape_only in _hits(text, lowered):
        if hs > scanned:
            delim = max(
                delim,
                text.rfind('"', scanned, hs),
                text.rfind("'", scanned, hs),
                text.rfind("\n", scanned, hs),
            )
            scanned = hs
        quoted = False
        if delim >= 0 and text[delim] != "\n":
            start = delim + 1
            if start not in quoted_by_start:
                quoted_by_start[start] = _quoted_key_span(text, start, he, scan)
            quoted = quoted_by_start[start]
        if quoted is not False:
            if quoted and quoted[0] not in seen_quoted:
                seen_quoted.add(quoted[0])
                spans.append(quoted)
            continue
        if escape_only or hs < run_end:
            continue  # not an unquoted key / the same run as the last hit
        s = hs
        while s > 0 and text[s - 1] in _KEY_CHARS:
            s -= 1
        e = he
        while e < n and text[e] in _KEY_CHARS:
            e += 1
        run_end = e
        if s > 0 and text[s - 1] == "/":
            continue  # a path component, not a key
        span = _unquoted_key_span(text, s, e, scan)
        if span:
            spans.append(span)
    return scan.resolve(spans)


def _format_spans(text, lowered):
    spans = []
    for row, regex in zip(_FORMAT_ROWS, _FORMAT_RES):
        if not any(needle in lowered for needle in row[2]):
            continue
        for match in regex.finditer(text):
            if "v" in regex.groupindex:
                start, end = match.span("v")
                # PEM body: keep the surrounding line breaks (real or
                # escaped at any level), so no escape sequence is cut.
                while start < end and text[start] in " \t\r\n":
                    start += 1
                while end > start and text[end - 1] in " \t\r\n":
                    end -= 1
                head = _ESCAPED_BREAKS_RE.match(text, start, end)
                if head is not None and head.end() < end:
                    start = head.end()
                while end - start > 2 and text[end - 1] in "nr":
                    run = _run_before(text, end - 1)
                    if not run or end - 1 - run <= start:
                        break
                    end -= run + 1
            else:
                start, end = match.span()
            if end > start:
                spans.append((start, end, MASK))
    return spans


def _mask(text):
    lowered = text.lower()
    spans = _format_spans(text, lowered) + _key_spans(text, lowered)
    if not spans:
        return text
    spans.sort(key=lambda span: (span[0], -span[1]))
    out = []
    pos = 0
    current = None
    for start, end, replacement in spans:
        if current is not None and start < current[1]:
            if end > current[1]:
                current[1] = end  # overlap: union, outer replacement kept
            continue
        if current is not None:
            out.append(text[pos:current[0]])
            out.append(current[2])
            pos = current[1]
        current = [start, end, replacement]
    out.append(text[pos:current[0]])
    out.append(current[2])
    out.append(text[current[1]:])
    return "".join(out)


# Masking-failure fallback (never raw text): a line is withheld when its
# lowercased text contains a token-format needle, or, with `_ - .` removed,
# an inventory word.
_WITHHOLD_NEEDLES = (
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "sk-", "akia",
    "asia", "xox", "sk_live_", "rk_live_", "aiza", "npm_", "eyj",
    "-----begin", "authorization",
)
_WITHHOLD_MARKER = "[actx] masking failed; %s lines withheld\n"


def _withheld_line(line):
    lowered = line.lower()
    if any(needle in lowered for needle in _WITHHOLD_NEEDLES):
        return True
    norm = lowered.replace("_", "").replace("-", "").replace(".", "")
    return any(word in norm for word in _INVENTORY)


def withhold_text(text):
    """Fallback when masking raised: drop every line that may carry a
    secret (_withheld_line; also every line of a `-----BEGIN` ...
    `-----END` block), keep the rest, append one marker line. Plain `in`
    checks only; if even this fails, everything is withheld. Known gap: a
    value on a line without a key or needle (the line after `"k":`, a
    multi-line container) is kept."""
    try:
        lines = text.split("\n")
        if lines[-1] == "":
            lines.pop()
        kept = []
        dropped = 0
        in_block = False
        for line in lines:
            if in_block or _withheld_line(line):
                dropped += 1
                lowered = line.lower()
                if "-----begin" in lowered:
                    in_block = True
                if "-----end" in lowered:
                    in_block = False
                continue
            kept.append(line + "\n")
        return "".join(kept) + _WITHHOLD_MARKER % dropped
    except Exception:
        return _WITHHOLD_MARKER % "all"


def redact_text(text):
    """Mask secret values (spans only). Never returns raw text on failure:
    if masking raises, withhold_text's line-drop fallback is returned."""
    if not text:
        return text
    try:
        return _mask(text)
    except Exception:
        return withhold_text(text)


def secret_bearing(text):
    """True when masking changes the text (the same detector rows, no second
    list). Fail-open to True: when detection fails, treat the output as
    secret-bearing."""
    if not text:
        return False
    try:
        return _mask(text) != text
    except Exception:
        return True
