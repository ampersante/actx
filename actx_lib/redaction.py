"""Secret value masking (TK-61): the single masking mechanism for the screen,
the tee file and tracking (`secret_bearing`).

A secret is found by data rows: known token formats (`_FORMAT_ROWS`) and
values that follow a secret-named key (`_SECRET_PATTERNS` + the closed
exclusions (a)-(d)). Only the value span is replaced by `MASK`; the line,
the key, quotes and delimiters outside the span stay byte-identical.
Idempotent: masking masked text changes nothing.

Value forms (spans):
1. Quoted key, JSON-style (`"k": v`, `'k': v`, escaped `\\"k\\":\\"v\\"`):
   a string -> its content; a number/true/false/null -> `"‹masked›"`; an
   object/array -> the whole container (bracket scan) -> `"‹masked›"`;
   any other unquoted value -> the run up to whitespace or `, ) ] }`.
2. Unquoted key, quoted value (`k = "v"`, `k: 'v'`, `--k "v"`) -> content.
3. Unquoted key, `=`, unquoted value -> the run up to whitespace or
   `; , & ) ] } " '`; a value starting with `{`/`[` takes the bracket scan
   first, then continues with that run.
4. Unquoted key, `:`, unquoted value -> the rest of the line up to
   whitespace + `#`, trailing whitespace excluded (inside an open "..."
   string on the line, up to its closing quote).
5. Flags (`--k v`, `--k=v`) -> the next token, up to whitespace or a quote.
No value exemptions (numbers, booleans, null, references, identifiers are
masked); no length floor. Known gaps: YAML block scalars, block mappings
and other multi-line values (only the PEM body is covered).
"""

import functools
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
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
        ("xox",),
        "xoxb-1234567890-abcdefghij",
        "xoxo-hugs-and-kisses",
        "Slack bot/user/app tokens",
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
        r"(?i)\bauthorization[\"']?[ \t]*[:=][ \t]*[\"']?(?:bearer|basic)[ \t]+"
        r"(?P<v>[^\s\"',;\\]+)",
        ("authorization",),
        "Authorization: Bearer abc.def-123",
        "Authorization: required",
        "HTTP Authorization header (RFC 9110 11.6.2)",
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
_QUOTED_KEY_MAX = 128
_HSPACE = " \t"
_TRAILING_SPACE = " \t\r"
_FORM3_STOP = frozenset(" \t\r\n\f\v;,&)]}\"'")
_FORM1_STOP = frozenset(" \t\r\n\f\v,)]}")
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


def _string_end(text, i, quote, stop_eol):
    """Index of the unescaped closing `quote` for a string whose content
    starts at i; None when absent (on this line when stop_eol)."""
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i
        if stop_eol and ch == "\n":
            return None
        i += 1
    return None


def _escaped_string_end(text, i):
    """Escaped form (a JSON string inside a JSON string): content starts at
    i, the string ends at the inner-unescaped `\\"`. Returns the index of
    that backslash; None when absent (a raw `"` or newline ends the search:
    the enclosing string is over)."""
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            inner = text[i + 1:i + 2]
            if inner == '"':
                return i
            i += 2
            if inner == "\\":  # inner backslash escapes the next inner char
                i += 2 if text[i:i + 1] == "\\" else 1
            continue
        if ch in '"\n':
            return None
        i += 1
    return None


def _bracket_end(text, i, escaped):
    """End (exclusive) of the container opening at text[i]: one depth
    counter for `{[` / `]}` regardless of kind; "..." and '...' strings are
    skipped, a backslash escapes the next character (in the escaped form
    `\\"` delimits strings); crosses lines; fail closed to end of text."""
    n = len(text)
    depth = 0
    while i < n:
        ch = text[i]
        if ch == "\\":
            if escaped and text[i + 1:i + 2] == '"':
                close = _escaped_string_end(text, i + 2)
                if close is None:
                    return n
                i = close + 2
                continue
            i += 2
            continue
        if ch in "\"'":
            close = _string_end(text, i + 1, ch, False)
            if close is None:
                return n
            i = close + 1
            continue
        if ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
            if depth <= 0:
                return i + 1
        i += 1
    return n


def _run_end(text, i, stop, stop_escaped_quote):
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in stop:
            break
        if stop_escaped_quote and ch == "\\" and text[i + 1:i + 2] in ("\"", "'"):
            break
        i += 1
    return i


def _in_open_string(text, line_start, pos):
    """True when pos sits inside an unclosed "..." string of its line."""
    inside = False
    i = line_start
    while i < pos:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == '"':
            inside = not inside
        i += 1
    return inside


# --- value spans -----------------------------------------------------------


def _quoted_value(text, v):
    """Span of a quoted value starting at v (`"`, `'` or escaped `\\"`);
    unclosed on its line -> to end of line. None when not quoted/empty."""
    if text.startswith('\\"', v):
        start = v + 2
        close = _escaped_string_end(text, start)
    elif text[v] in "\"'":
        start = v + 1
        close = _string_end(text, start, text[v], True)
    else:
        return None
    end = close if close is not None else _rstrip_end(text, start, _eol(text, start))
    return (start, end, MASK) if end > start else ()


def _form1_value(text, v, escaped):
    """Value after a quoted key (JSON-style)."""
    quoted = _quoted_value(text, v)
    if quoted is not None:
        return quoted or None
    qmask = '\\"%s\\"' % MASK if escaped else '"%s"' % MASK
    if text[v] in "{[":
        return (v, _bracket_end(text, v, escaped), qmask)
    end = _run_end(text, v, _FORM1_STOP, False)
    if end == v:
        return None
    literal = _JSON_LITERAL_RE.fullmatch(text, v, end) is not None
    return (v, end, qmask if literal else MASK)


def _form4_value(text, v, sep_end, key_start):
    line_start = text.rfind("\n", 0, key_start) + 1
    eol = _eol(text, v)
    if text[v] == "#" and v > sep_end:
        return None  # `k: #...` is a comment
    end = eol
    comment = _COMMENT_RE.search(text, v, eol)
    if comment is not None:
        end = comment.start()
    if _in_open_string(text, line_start, key_start):
        close = _string_end(text, v, '"', True)
        if close is not None and close < end:
            end = close
    end = _rstrip_end(text, v, end)
    return (v, end, MASK) if end > v else None


def _skip_hspace(text, i):
    n = len(text)
    while i < n and text[i] in _HSPACE:
        i += 1
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


def _quoted_key_span(text, hs, he):
    """Value span for a quoted key around the hit [hs, he); False when the
    hit is not inside a quoted key; None when it is but nothing to mask."""
    i = hs
    limit = max(0, hs - _QUOTED_KEY_MAX)
    while i > limit and text[i - 1] not in "\"'\n":
        i -= 1
    if i == 0 or text[i - 1] not in "\"'":
        return False
    quote = text[i - 1]
    escaped = quote == '"' and i >= 2 and text[i - 2] == "\\"
    j = he
    limit = min(len(text), he + _QUOTED_KEY_MAX)
    while j < limit and text[j] not in "\"'\n\\":
        j += 1
    if escaped:
        if text[j:j + 2] != '\\"':
            return False
        close_end = j + 2
    else:
        if text[j:j + 1] != quote:
            return False
        close_end = j + 1
    kind, sep_end = _separator(text, close_end)
    if kind is None:
        return False
    key = text[i:j]
    if not _is_secret_key(key):
        return None
    v = _skip_hspace(text, sep_end)
    if v >= len(text) or text[v] in "\r\n":
        return None
    return _form1_value(text, v, escaped)


def _unquoted_key_span(text, s, e):
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
    quoted = _quoted_value(text, v)
    if quoted is not None:  # form 2
        return quoted or None
    if flag:  # form 5
        end = _run_end(text, v, _FLAG_STOP, True)
    elif kind == ":":  # form 4
        return _form4_value(text, v, sep_end, s)
    else:  # form 3
        end = v
        if text[v] in "{[":
            end = _bracket_end(text, v, False)
        end = _run_end(text, end, _FORM3_STOP, True)
    return (v, end, MASK) if end > v else None


def _key_spans(text, lowered):
    spans = []
    seen_quoted = set()
    seen_runs = set()
    n = len(text)
    if len(lowered) == n:
        hits = _CANDIDATE_RE.finditer(lowered)
    else:
        hits = _CANDIDATE_RE_I.finditer(text)
    for hit in hits:
        hs, he = hit.span()
        quoted = _quoted_key_span(text, hs, he)
        if quoted is not False:
            if quoted and quoted[0] not in seen_quoted:
                seen_quoted.add(quoted[0])
                spans.append(quoted)
            continue
        s = hs
        while s > 0 and text[s - 1] in _KEY_CHARS:
            s -= 1
        e = he
        while e < n and text[e] in _KEY_CHARS:
            e += 1
        if s in seen_runs:
            continue
        seen_runs.add(s)
        if s > 0 and text[s - 1] == "/":
            continue  # a path component, not a key
        span = _unquoted_key_span(text, s, e)
        if span:
            spans.append(span)
    return spans


def _format_spans(text, lowered):
    spans = []
    for row, regex in zip(_FORMAT_ROWS, _FORMAT_RES):
        if not any(needle in lowered for needle in row[2]):
            continue
        for match in regex.finditer(text):
            if "v" in regex.groupindex:
                start, end = match.span("v")
                # PEM body: keep the surrounding line breaks (real or \n-escaped).
                while start < end and text[start] in " \t\r\n":
                    start += 1
                while end > start and text[end - 1] in " \t\r\n":
                    end -= 1
                if text.startswith("\\n", start) and end - start > 2:
                    start += 2
                if text.endswith("\\n", start, end) and end - start > 2:
                    end -= 2
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


def redact_text(text):
    """Mask secret values (spans only). Fail-open: on internal error return
    the input unchanged (callers also own a fail-open path around it)."""
    if not text:
        return text
    try:
        return _mask(text)
    except Exception:
        return text


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
