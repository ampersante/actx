"""TK-61 C1: secret VALUE masking (plan TK-61 Design §3, Tests §3).

Exact-output rows (only the span replaced), negatives byte-identical, JSON
validity (raw parses => masked parses), idempotence, and a generated
differential against the frozen pre-TK-61 key predicate with an oracle
built from the plan's rules (not from actx_lib.redaction).
"""

import json
import re
import sys
import unittest

from actx_lib import redaction

M = "‹masked›"
QM = '"%s"' % M
EQM = '\\"%s\\"' % M


def _pretty(obj, indent=2):
    return json.dumps(obj, indent=indent, ensure_ascii=False)


DOCKER_INSPECT = _pretty(
    [{"Id": "abc", "Config": {"Env": ["POSTGRES_PASSWORD=example", "PATH=/usr/bin"],
                              "Image": "postgres:16"}}],
    indent=4,
)
DOCKER_INSPECT_MASKED = _pretty(
    [{"Id": "abc", "Config": {"Env": ["POSTGRES_PASSWORD=" + M, "PATH=/usr/bin"],
                              "Image": "postgres:16"}}],
    indent=4,
)

KUBECTL_DESCRIBE_ENV = (
    "Containers:\n"
    "  mysql:\n"
    "    Image:      mysql:8\n"
    "    Environment:\n"
    "      MYSQL_ROOT_PASSWORD:  123456\n"
    "      MYSQL_DATABASE:       app\n"
    "    Mounts:     <none>\n"
)

DOT_ENV = (
    "DB_HOST=localhost\n"
    "DB_PASSWORD=hunter2\n"
    'API_TOKEN="abc 123"\n'
    "DEBUG=true\n"
)

YAML_DOC = (
    "database:\n"
    "  host: db\n"
    "  password: my secret, with commas\n"
    "  token: abc123  # rotated monthly\n"
    "  user: app\n"
)

PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA\n"
    "abcdef==\n"
    "-----END RSA PRIVATE KEY-----\n"
)

# (input, exact expected output)
POSITIVE_ROWS = (
    # value forms: docker/kubectl env blocks, .env, YAML
    ('"POSTGRES_PASSWORD=example",', '"POSTGRES_PASSWORD=%s",' % M),
    (DOCKER_INSPECT, DOCKER_INSPECT_MASKED),
    (KUBECTL_DESCRIBE_ENV, KUBECTL_DESCRIBE_ENV.replace("123456", M)),
    (DOT_ENV, DOT_ENV.replace("hunter2", M).replace("abc 123", M)),
    (
        YAML_DOC,
        YAML_DOC.replace("my secret, with commas", M).replace("abc123", M),
    ),
    ("MYSQL_ROOT_PASSWORD:  123456\r\n", "MYSQL_ROOT_PASSWORD:  %s\r\n" % M),
    # compact / escaped JSON
    ('{"password":1234,"x":"y"}', '{"password":%s,"x":"y"}' % QM),
    ('{\\"password\\":\\"v\\"}', '{\\"password\\":\\"%s\\"}' % M),
    (
        json.dumps({"cmd": json.dumps({"password": "v", "a": 1})}),
        json.dumps({"cmd": json.dumps({"password": M, "a": 1}, ensure_ascii=False)},
                   ensure_ascii=False),
    ),
    # logfmt, libpq, ADO, comma lists, URL query, table cell
    ("level=info password=s3cret user=bob", "level=info password=%s user=bob" % M),
    ("host=db password=s3cret dbname=app", "host=db password=%s dbname=app" % M),
    ("Server=x;Password=s3cret;Database=y", "Server=x;Password=%s;Database=y" % M),
    ("password=s3cret, user=bob", "password=%s, user=bob" % M),
    ("https://h/p?token=x&a=1", "https://h/p?token=%s&a=1" % M),
    ("| password=hunter2 |", "| password=%s |" % M),
    # flags
    ("--password hunter2 --user bob", "--password %s --user bob" % M),
    ("--token=abc123 -v", "--token=%s -v" % M),
    ('--api-key "a b" x', '--api-key "%s" x' % M),
    # code line: the `:` span runs to end of line (accepted code cost)
    ("def f(password: str, token=None):", "def f(password: %s" % M),
    ("password = os.environ", "password = %s" % M),
    ('{"password": password}', '{"password": %s}' % M),
    # plural, undivided and qualifier-first keys
    ("REGISTRY_CREDENTIALS=x", "REGISTRY_CREDENTIALS=%s" % M),
    ("secrets: x", "secrets: %s" % M),
    ("PGPASSWORD=hunter2", "PGPASSWORD=%s" % M),
    ("id_token=opaque", "id_token=%s" % M),
    # numbers, booleans, null, references - no value exemptions
    ("password=12345678", "password=%s" % M),
    ('{"password": true}', '{"password": %s}' % QM),
    ('{"token": null}', '{"token": %s}' % QM),
    ('{"password": 1.5e3}', '{"password": %s}' % QM),
    ("token: ${GH_TOKEN}", "token: %s" % M),
    ("token=$GH_TOKEN", "token=%s" % M),
    ("api_key: {{ secrets.KEY }}", "api_key: %s" % M),
    # form-3 run stops at `}`: the reference body is masked, the brace stays
    ("token=${TOKEN}", "token=%s}" % M),
    # baseline examples (plan §3)
    ("passphrase=x", "passphrase=%s" % M),
    ("signing_key=x", "signing_key=%s" % M),
    ("AccessKey=x", "AccessKey=%s" % M),
    ("AWS_ACCESS_KEY_ID=EXAMPLEKEYEXAMPLE", "AWS_ACCESS_KEY_ID=%s" % M),
    # JSON containers -> "‹masked›" (compact, spaced, pretty, escaped)
    ('{"credentials": {"u": "x"}}', '{"credentials": %s}' % QM),
    ('{"credentials":{"u":"x"}}', '{"credentials":%s}' % QM),
    ('{"tokens":["a","b"]}', '{"tokens":%s}' % QM),
    (_pretty({"credentials": {"u": "x"}}), _pretty({"credentials": M})),
    (_pretty({"tokens": ["a", "b"]}), _pretty({"tokens": M})),
    (
        _pretty({"a": 1, "credentials": {"u": "x", "n": [1, {"p": "q"}]}, "z": 2}),
        _pretty({"a": 1, "credentials": M, "z": 2}),
    ),
    (
        json.dumps({"s": json.dumps({"credentials": {"u": "x"}})}),
        '{"s": "{\\"credentials\\": %s}"}' % EQM,
    ),
    (
        json.dumps({"s": json.dumps({"tokens": ["a", "b"], "k": 1})}),
        '{"s": "{\\"tokens\\": %s, \\"k\\": 1}"}' % EQM,
    ),
    # brackets, `]` and `\"` inside strings are skipped by the scan
    ('{"password": {"u": "a}b", "v": "[c"}}', '{"password": %s}' % QM),
    ("{'password': {'u': 'a}b'}}", "{'password': %s}" % QM),
    ('{"password": {"u": "a]b\\"}c", "v": "[d"}, "k": 1}',
     '{"password": %s, "k": 1}' % QM),
    # unbalanced container: fail closed to end of text
    ('{"password": {"u": "x"\nnext line\n', '{"password": %s' % QM),
    # form-3 containers
    ("credentials={u:x,p:y}", "credentials=%s" % M),
    ("userPassword={SSHA512}abcdef", "userPassword=%s" % M),
    ('credentials={u:"a}b",p:y} next', "credentials=%s next" % M),
    # mismatched brackets: the single depth counter closes at `]` - the
    # malformed-input residual (plan Weakest point 7) is pinned here
    ("credentials={a]x,y}", "credentials=%s,y}" % M),
    # positive counterparts of the exclusions
    ("cached_token=x", "cached_token=%s" % M),
    ("output_token=x", "output_token=%s" % M),
    ("tokenize_key=x", "tokenize_key=%s" % M),
    ("tokenizer_auth=x", "tokenizer_auth=%s" % M),
    ("secret_url=https://h/x", "secret_url=%s" % M),
    ("token_url=https://h/x", "token_url=%s" % M),
    ("PWD=/app", "PWD=%s" % M),
    ("OLDPWD=/home/u", "OLDPWD=%s" % M),
    ("DSN=x;UID=u;PWD=secret", "DSN=x;UID=u;PWD=%s" % M),
    # widened spellings the baseline substring test did not flag
    ("ACCESS-KEY=x", "ACCESS-KEY=%s" % M),
    ("access-key: x", "access-key: %s" % M),
    ("x-api-key: abc", "x-api-key: %s" % M),
    ("passwd=x", "passwd=%s" % M),
    # a key inside a JSON string value keeps the document valid
    ('{"msg": "password: x y", "a": 1}', '{"msg": "password: %s", "a": 1}' % M),
    # an unquoted value that ends the enclosing JSON string: the span stops
    # at the string's closing quote; literals follow the key's quoting level
    ('{"a":"x \\"password\\": y"}', '{"a":"x \\"password\\": %s"}' % M),
    ('{"a":"x \\"password\\": 12"}', '{"a":"x \\"password\\": %s"}' % EQM),
    ('{"a":"x \\"password\\": y z"}', '{"a":"x \\"password\\": %s z"}' % M),
    (json.dumps({"a": 'x "password": y\\'}), '{"a": "x \\"password\\": %s"}' % M),
    ('{"a": "x \'password\': y"}', '{"a": "x \'password\': %s"}' % M),
    ('{"a": "x \'password\': 12"}', "{\"a\": \"x 'password': '%s'\"}" % M),
    ('{"a": "x \'password\': {\'u\': 1}"}', "{\"a\": \"x 'password': '%s'\"}" % M),
    ('{"a": "--password y\\\\"}', '{"a": "--password %s"}' % M),
    ('{"a": "password=\'abc"}', '{"a": "password=\'%s"}' % M),
    ('{"a": "password=y\\\\"}', '{"a": "password=%s"}' % M),
    # known token formats
    ("using ghp_" + "a1B2c3D4e5" * 3 + "a1B2c3 now", "using %s now" % M),
    ("key sk-ant-api03-abcdefghij0123456789 end", "key %s end" % M),
    ("AKIAIOSFODNN7EXAMPLE", M),
    ("postgres://app:pa55w0rd@db:5432/app", "postgres://app:%s@db:5432/app" % M),
    ("-H 'Authorization: Bearer abc.def-123'", "-H 'Authorization: Bearer %s'" % M),
    (PEM, "-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\n" % M),
    (
        '{"k": "-----BEGIN PRIVATE KEY-----\\nMIIE\\n-----END PRIVATE KEY-----\\n"}',
        '{"k": "-----BEGIN PRIVATE KEY-----\\n%s\\n-----END PRIVATE KEY-----\\n"}' % M,
    ),
)

# Exclusion rules (a)-(d) only; each line byte-identical.
NEGATIVE_ROWS = (
    "tokenizer",
    '{"tokenizer": "gpt2"}',
    "tokenizer_path: /models/x",
    "input_tokens: 123",
    "completion_tokens: 45",
    "cache_read_tokens: 6",
    "max_tokens: 10000000",
    "n_tokens: 5",
    "token_count: 123",
    "token_type: Bearer",
    "secret_name: db-creds",
    "password_file: /run/secrets/db",
    "max_password_len=64",
    "cached_tokens: 7",
    "NextToken: abc",
    "nextPageToken: abc",
    '{"next_page_token": "abc", "continuation_token": "d"}',
    "page_token=abc",
    '{"usage": {"input_tokens": 3, "output_tokens": 5}, "max_tokens": 10}',
    _pretty({"usage": {"prompt_tokens": 3, "completion_tokens": 5, "total_tokens": 8}}),
)

# Secret-free text: byte-identical (tabs, CRLF, trailing spaces, unicode,
# prose with secret words but no key-value form, paths).
FIDELITY_CORPUS = (
    "commit 1a2b3c4d\n"
    "Author: Dev <dev@example.com>\n"
    "\tfix: keyboard layout for monkey business\r\n"
    '{"name": "actx", "items": [1, 2, 3], "nested": {"ok": true}}\n'
    "def tokenize_text(s):\n"
    "    return s.split()  \n"
    "ünïcödé — 日本語 — 🚀   \n"
    "the password is required; the token expired\n"
    "path=/usr/local/bin:/opt/homebrew/bin\n"
    "cat /etc/passwd: done\n"
    "https://example.com:8443/api?page=2&limit=50\n"
    "ssh://git@github.com/org/repo.git\n"
    "sketch task-list-of-things ghp_short sk-learn-is-a-library\n"
    "  x = 1\n\n\n"
)


def _parses(text):
    try:
        json.loads(text)
    except ValueError:
        return False
    return True


class ExactRowTests(unittest.TestCase):
    def test_positive_rows_exact_output(self):
        for raw, expected in POSITIVE_ROWS:
            with self.subTest(raw=raw):
                self.assertEqual(redaction.redact_text(raw), expected)

    def test_negative_rows_byte_identical(self):
        for raw in NEGATIVE_ROWS:
            with self.subTest(raw=raw):
                self.assertEqual(redaction.redact_text(raw), raw)
                self.assertFalse(redaction.secret_bearing(raw))

    def test_secret_free_corpus_byte_identical(self):
        self.assertEqual(redaction.redact_text(FIDELITY_CORPUS), FIDELITY_CORPUS)
        self.assertFalse(redaction.secret_bearing(FIDELITY_CORPUS))

    def test_json_validity_preserved(self):
        checked = 0
        for raw, _expected in POSITIVE_ROWS:
            if _parses(raw):
                checked += 1
                with self.subTest(raw=raw):
                    self.assertTrue(_parses(redaction.redact_text(raw)))
        self.assertGreaterEqual(checked, 15)

    def test_idempotent(self):
        for raw, _expected in POSITIVE_ROWS:
            once = redaction.redact_text(raw)
            with self.subTest(raw=raw):
                self.assertEqual(redaction.redact_text(once), once)

    def test_secret_bearing_is_redact_text_changed(self):
        for raw, expected in POSITIVE_ROWS:
            with self.subTest(raw=raw):
                self.assertNotEqual(expected, raw)
                self.assertTrue(redaction.secret_bearing(raw))

    def test_hunter2_never_survives(self):
        for raw, _expected in POSITIVE_ROWS:
            if "hunter2" in raw:
                self.assertNotIn("hunter2", redaction.redact_text(raw))


class FormatRowTests(unittest.TestCase):
    """Generated from the detector rows' own examples."""

    def test_rows_are_complete_data(self):
        self.assertGreaterEqual(len(redaction._FORMAT_ROWS), 11)
        for row in redaction._FORMAT_ROWS:
            name, pattern, needles, positive, negative, source = row
            self.assertTrue(name and pattern and needles and source, row)
            self.assertTrue(any(n in positive.lower() for n in needles), name)
            self.assertEqual([n for n in needles if n != n.lower()], [], name)

    def test_positive_example_masked_line_kept(self):
        for name, _p, _n, positive, _neg, _s in redaction._FORMAT_ROWS:
            line = "before %s after" % positive
            out = redaction.redact_text(line)
            with self.subTest(row=name):
                self.assertIn(M, out)
                self.assertTrue(out.startswith("before "))
                self.assertTrue(out.endswith(" after"))

    def test_negative_example_untouched(self):
        for name, _p, _n, _pos, negative, _s in redaction._FORMAT_ROWS:
            line = "before %s after" % negative
            with self.subTest(row=name):
                self.assertEqual(redaction.redact_text(line), line)


# --- generated differential -------------------------------------------------

# Frozen copy of the pre-TK-61 inventory and predicate (redaction.py at
# 5add1d3, `_SECRET_PATTERNS` + `_is_secret_key`).
BASELINE_PATTERNS = (
    "secret", "token", "password", "accesskey", "credential",
    "aws_access_key_id", "aws_secret_access_key", "api_key", "apikey",
    "private_key", "secret_key", "client_secret", "access_key",
    "signing_key", "passphrase",
)


def baseline_is_secret_key(key):
    lowered = key.lower()
    return any(pattern in lowered for pattern in BASELINE_PATTERNS)


# Plan-rule oracle (TK-61 §3), written independently of actx_lib.redaction.
PLAN_INVENTORY = tuple(p.replace("_", "") for p in BASELINE_PATTERNS) + ("passwd", "pwd")
RULE_A = {"tokenizer", "tokenizers", "tokenize", "detokenize", "detokenizer"}
RULE_B = {"count", "type", "kind", "name", "file", "path", "dir", "ttl", "timeout",
          "expiry", "expires", "len", "length", "size", "limit"}
RULE_C = {"max", "min", "n", "num", "total", "input", "output", "prompt",
          "completion", "cached", "cache", "reasoning", "used", "remaining"}
RULE_D = {"nexttoken", "nextpagetoken", "pagetoken", "continuationtoken"}


def plan_norm(key):
    return re.sub(r"[_.\-]", "", key).lower()


def plan_segments(key):
    segs = []
    for part in re.split(r"[_.\-]+", key):
        segs += [s.lower() for s in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+", part)]
    return segs


def plan_exclusion(key):
    """Name of the rule (a)-(d) that frees the key, or None."""
    norm = plan_norm(key)
    segs = plan_segments(key)
    if norm in RULE_A:
        return "a"
    if segs and segs[-1] in RULE_B and norm not in PLAN_INVENTORY:
        return "b"
    if "tokens" in segs and segs[0] in RULE_C:
        rest = "".join(s for s in segs if s != "tokens")
        if not any(p in rest for p in PLAN_INVENTORY):
            return "c"
    if norm in RULE_D:
        return "d"
    return None


def plan_is_secret(key):
    return any(p in plan_norm(key) for p in PLAN_INVENTORY) and plan_exclusion(key) is None


# test_redaction.py:30-44 key literals (baseline PatternTests)
BASELINE_TEST_KEYS = (
    "api_key", "apikey", "API_KEY", "AWS_API_KEY", "private_key",
    "client_secret", "signing_key", "passphrase", "AccessKey",
)


def _camel(key):
    parts = [p for p in key.split("_") if p]
    if len(parts) < 2:
        return key
    return parts[0].lower() + "".join(p[:1].upper() + p[1:].lower() for p in parts[1:])


SPELLINGS = (
    ("as-is", lambda k: k),
    ("plural", lambda k: k + "s"),
    ("upper", lambda k: k.upper()),
    ("camel", _camel),
    ("kebab", lambda k: k.replace("_", "-")),
)
PREFIXES = ("", "PG", "MYSQL_", "AWS_", "GH_", "NPM_", "id_", "x_")
SUFFIXES = ("", "_id", "_value")

V = "Zq7vW1"
V2 = "Yp3uX8"
# (template, oracle); {k} is the key, the oracle replaces only the value span
DIFF_FORMS = (
    ("{k}=%s" % V, "{k}=%s" % M),
    ("{k}=%s other=1" % V, "{k}=%s other=1" % M),
    ("{k}: %s" % V, "{k}: %s" % M),
    ('{{"{k}": "%s"}}' % V, '{{"{k}": "%s"}}' % M),
    ('{{"{k}": 123}}', '{{"{k}": %s}}' % QM),
    ('{{"{k}": {{"n": "%s"}}}}' % V, '{{"{k}": %s}}' % QM),
    ('{{"{k}": ["%s","%s"]}}' % (V, V2), '{{"{k}": %s}}' % QM),
    ("--{k} %s" % V, "--{k} %s" % M),
    ("export {k}=%s" % V, "export {k}=%s" % M),
    # review fixes: JSON whitespace (LF, CR, CRLF) around `:` after a quoted
    # key; string-prefixed literals after `=` and flags
    ('{{"{k}":\n  "%s"}}' % V, '{{"{k}":\n  "%s"}}' % M),
    ('{{\r\n"{k}"\r\n:\r\n123}}', '{{\r\n"{k}"\r\n:\r\n%s}}' % QM),
    ('{{\n "{k}":\n {{"n": "%s"}}\n}}' % V, '{{\n "{k}":\n %s\n}}' % QM),
    ("{k}=b'%s'" % V, "{k}=b'%s'" % M),
    ('--{k}=rb"%s"' % V, '--{k}=rb"%s"' % M),
)


def generated_keys():
    base = list(dict.fromkeys(BASELINE_PATTERNS + ("passwd", "pwd") + BASELINE_TEST_KEYS))
    keys = []
    for key in base:
        for _name, spell in SPELLINGS:
            for prefix in PREFIXES:
                for suffix in SUFFIXES:
                    keys.append(prefix + spell(key) + suffix)
    return list(dict.fromkeys(keys))


class GeneratedDifferentialTests(unittest.TestCase):
    def test_key_predicate_matches_plan_oracle(self):
        keys = generated_keys() + [row.split(":")[0].split("=")[0] for row in NEGATIVE_ROWS
                                   if not row.startswith("{")]
        for key in keys:
            with self.subTest(key=key):
                self.assertEqual(redaction._is_secret_key(key), plan_is_secret(key))

    def test_differential_masks_every_value_span_exactly(self):
        keys = generated_keys()
        excluded = sorted(
            k for k in keys if baseline_is_secret_key(k) and plan_exclusion(k)
        )
        widened = sorted(
            k for k in keys if plan_is_secret(k) and not baseline_is_secret_key(k)
        )
        lost = sorted(
            k for k in keys
            if baseline_is_secret_key(k) and not plan_is_secret(k) and k not in excluded
        )
        print(
            "\n[TK-61 differential] %d keys x %d forms; baseline-flagged but "
            "excluded by (a)-(d): %r; widened (masked now, baseline missed): %d"
            % (len(keys), len(DIFF_FORMS), excluded, len(widened)),
            file=sys.stderr,
        )
        self.assertEqual(lost, [])
        self.assertIn("access-key", widened)
        self.assertIn("pwd", widened)
        for key in keys:
            secret = plan_is_secret(key)
            for template, oracle in DIFF_FORMS:
                line = template.format(k=key)
                out = redaction.redact_text(line)
                with self.subTest(key=key, line=line):
                    if secret:
                        self.assertEqual(out, oracle.format(k=key))
                        for value in (V, V2, "123"):
                            self.assertNotIn(value, out)
                    else:
                        self.assertEqual(out, line)
                    if line.startswith("{"):
                        self.assertTrue(_parses(line))
                        self.assertTrue(_parses(out))


# Unquoted values under quoted keys, placed last before a closing quote.
EMBED_EXTRA_FORMS = (
    '"{k}": %s' % V,
    '"{k}": 123',
    '"{k}": true',
    "'{k}': %s" % V,
    "'{k}': 123",
    "'{k}': {{'n': '%s'}}" % V,
    # review fixes: a line break between `:` and the value
    '"{k}":\n %s' % V,
    "'{k}':\n '%s'" % V,
    "'{k}':\r\n{{'n': '%s'}}" % V,
)


class JsonStringEmbeddingSweepTests(unittest.TestCase):
    """Every differential form (and unquoted values under quoted keys),
    embedded in a JSON string value via json.dumps as the last token
    before the string's closing quote: the result parses, V is gone."""

    def test_embedded_forms_keep_json_valid(self):
        keys = [k for k in generated_keys() if plan_is_secret(k)]
        templates = [t for t, _oracle in DIFF_FORMS] + list(EMBED_EXTRA_FORMS)
        checked = 0
        for key in keys:
            for template in templates:
                line = template.format(k=key)
                for doc in (
                    json.dumps({"s": line}),
                    json.dumps({"s": "pre " + line, "t": [1]}),
                    json.dumps([line + "\\"]),
                ):
                    out = redaction.redact_text(doc)
                    checked += 1
                    with self.subTest(doc=doc):
                        self.assertTrue(_parses(out), out)
                        for value in (V, V2):
                            self.assertNotIn(value, out)
        self.assertGreater(checked, 10000)


# --- TK-61 review fixes: red on 475301f, green after ------------------------

S = "Hq9xR4"
LONG_KEY = "password_" + "x" * 128
LONG_KEY_BACK = "x" * 200 + "_token"
U_KEY_DOC = '{"\\u0070assword": "%s"}' % S
SLACK_POSITIVE = (
    "xoxa-2-1234567890-abcdefghij",
    "xoxb-1234567890-abcdefghij",
    "xoxc-1234567890-abcdefghij",
    "xoxe-1-1234567890-abcdefghij",
    "xoxp-1234567890-abcdefghij",
    "xoxr-1234567890-abcdefghij",
    "xoxs-1234567890-abcdefghij",
    "xoxe.xoxp-1-1234567890-abcdefghij",
    "xoxe.xoxb-1-1234567890-abcdefghij",
)
SLACK_NEGATIVE = (
    "xoxo-hugs-and-kisses",
    "xoxz-1234567890-abcdefghij",
    "xoxc-short",
    "xoxe.xoxo-1234567890-abcdefghij",
    "fooxoxb-1234567890-abcdefghij",
)

# (input, exact expected output)
REVIEW_FIX_ROWS = (
    # 1. JSON whitespace (LF, CR, CRLF) on both sides of `:` after a quoted key
    ('{"password":\n  "%s"}' % S, '{"password":\n  "%s"}' % M),
    ('{"password":\r\n"%s"}' % S, '{"password":\r\n"%s"}' % M),
    ('{"password":\r"%s"}' % S, '{"password":\r"%s"}' % M),
    ('{\n  "password"\n  : "%s"}' % S, '{\n  "password"\n  : "%s"}' % M),
    ('{"password"\r\n:\r\n12}', '{"password"\r\n:\r\n%s}' % QM),
    ('{"password":\n\ttrue}', '{"password":\n\t%s}' % QM),
    ('{\n  "credentials":\n  {"u": "%s"}\n}' % S, '{\n  "credentials":\n  %s\n}' % QM),
    ('{\n "tokens":\n [\n  "%s"\n ]\n}' % S, '{\n "tokens":\n %s\n}' % QM),
    ("{'password':\n '%s'}" % S, "{'password':\n '%s'}" % M),
    (
        json.dumps({"s": '{"password":\n "%s"}' % S}),
        '{"s": "{\\"password\\":\\n \\"%s\\"}"}' % M,
    ),
    (
        json.dumps({"s": '{"password"\r\n: 12}'}),
        '{"s": "{\\"password\\"\\r\\n: %s}"}' % EQM,
    ),
    (
        json.dumps({"s": "{'password':\n '%s'}" % S}),
        "{\"s\": \"{'password':\\n '%s'}\"}" % M,
    ),
    # the same document printed as a repr (pytest diffs): `\n` escapes
    (repr('{"password":\n  "%s"}' % S), "'{\"password\":\\n  \"%s\"}'" % M),
    # 2. no quoted-key length window
    (json.dumps({LONG_KEY: S}), json.dumps({LONG_KEY: M}, ensure_ascii=False)),
    (json.dumps({LONG_KEY_BACK: 7}), json.dumps({LONG_KEY_BACK: M}, ensure_ascii=False)),
    (
        json.dumps({"s": json.dumps({LONG_KEY: S})}),
        json.dumps({"s": json.dumps({LONG_KEY: M}, ensure_ascii=False)},
                   ensure_ascii=False),
    ),
    ("{'%s': '%s'}" % (LONG_KEY, S), "{'%s': '%s'}" % (LONG_KEY, M)),
    # 4. string-prefixed literals: the prefix stays, the quoted content is masked
    ("password=b'%s'" % S, "password=b'%s'" % M),
    ("password=u'%s'" % S, "password=u'%s'" % M),
    ("password=f'%s'" % S, "password=f'%s'" % M),
    ("password=r'%s'" % S, "password=r'%s'" % M),
    ('password=b"%s"' % S, 'password=b"%s"' % M),
    ("password=rb'%s'" % S, "password=rb'%s'" % M),
    ('password=Rb"%s" user=bob' % S, 'password=Rb"%s" user=bob' % M),
    ("password = f'%s %s'" % (S, S), "password = f'%s'" % M),
    ("--password=b'%s' -v" % S, "--password=b'%s' -v" % M),
    ("--password b'%s'" % S, "--password b'%s'" % M),
    ("{'password': b'%s'}" % S, "{'password': b'%s'}" % M),
    ('{"password": rb"%s"}' % S, '{"password": rb"%s"}' % M),
    # 5. \\uXXXX-escaped key spelling is decoded before the secret-name test
    (U_KEY_DOC, '{"\\u0070assword": "%s"}' % M),
    ('{"pass\\u0077ord": 12}', '{"pass\\u0077ord": %s}' % QM),
    ('{"\\u0050ASSWORD": "%s"}' % S, '{"\\u0050ASSWORD": "%s"}' % M),
    ('{"password\\u005fx": "%s"}' % S, '{"password\\u005fx": "%s"}' % M),
    ('{"\\u0074oken": {"a": "%s"}}' % S, '{"\\u0074oken": %s}' % QM),
    ("{'\\u0070wd': '%s'}" % S, "{'\\u0070wd': '%s'}" % M),
    (json.dumps({"s": U_KEY_DOC}), '{"s": "{\\"\\\\u0070assword\\": \\"%s\\"}"}' % M),
    # 6. Slack prefixes; Authorization `token` scheme (GitHub), any case
    ("t=%s end" % SLACK_POSITIVE[2], "t=%s end" % M),
    ("Authorization: token %s" % S, "Authorization: token %s" % M),
    ("AUTHORIZATION: TOKEN %s" % S, "AUTHORIZATION: TOKEN %s" % M),
    ("-H 'Authorization: Token %s'" % S, "-H 'Authorization: Token %s'" % M),
    ('{"Authorization": "token %s"}' % S, '{"Authorization": "token %s"}' % M),
)

# Byte-identical: cross-line `:` is for quoted keys only; form 4 never
# takes the next line; decoded keys outside the inventory stay.
REVIEW_FIX_NEGATIVE_ROWS = (
    "password:\nuser: bob\n",
    "password:\r\nuser: bob\r\n",
    "password =\nuser=bob\n",
    'print("password")\nnext: 1\n',
    'x = "password"\ny = 1\n',
    '{"\\u0070ath": "/usr/bin"}',
    '{"\\u0074okenizer": "gpt2"}',
    "Authorization: required",
    # a key ending its enclosing JSON string has no value: the document
    # stays byte-identical (and valid)
    json.dumps({"a": 'x "password": ', "b": "y"}),
    json.dumps({"a": "x 'password': ", "b": "y"}),
    json.dumps({"a": 'x "password":\n', "b": "y"}),
) + SLACK_NEGATIVE


class ReviewFixRowTests(unittest.TestCase):
    def test_rows_exact_output(self):
        for raw, expected in REVIEW_FIX_ROWS:
            with self.subTest(raw=raw):
                out = redaction.redact_text(raw)
                self.assertEqual(out, expected)
                self.assertNotIn(S, out)
                self.assertEqual(redaction.redact_text(out), out)
                if _parses(raw):
                    self.assertTrue(_parses(out), out)

    def test_json_rows_counted(self):
        self.assertGreaterEqual(sum(_parses(raw) for raw, _e in REVIEW_FIX_ROWS), 18)

    def test_negative_rows_byte_identical(self):
        for raw in REVIEW_FIX_NEGATIVE_ROWS:
            with self.subTest(raw=raw):
                self.assertEqual(redaction.redact_text(raw), raw)

    def test_slack_prefixes_masked_whole(self):
        for token in SLACK_POSITIVE:
            with self.subTest(token=token):
                self.assertEqual(redaction.redact_text("a %s b" % token), "a %s b" % M)

    def test_each_key_evaluated_once_whatever_its_length(self):
        # No length window (finding 2) without a quadratic cost: hits inside
        # one quoted key or one unquoted key run share one evaluation
        # (counted calls, not wall-clock).
        from unittest import mock

        cases = (
            ('{"' + "token " * 2000 + '": 1}', "_quoted_key_span",
             '{"' + "token " * 2000 + '": %s}' % QM),
            ("token" * 2000 + "=v", "_unquoted_key_span", "token" * 2000 + "=" + M),
        )
        for text, name, expected in cases:
            real = getattr(redaction, name)
            with self.subTest(name=name), mock.patch.object(
                redaction, name, side_effect=real
            ) as spy:
                self.assertEqual(redaction.redact_text(text), expected)
                self.assertEqual(spy.call_count, 1)

    def test_escaped_key_decoder(self):
        for key, secret in (
            ("\\u0070assword", True), ("\\\\u0070assword", True),
            ("\\u0070ath", False), ("pass\\u0057ORD", True),
        ):
            with self.subTest(key=key):
                self.assertEqual(redaction._is_secret_key(redaction._decode_key(key)), secret)


class MaskingFailureFallbackTests(unittest.TestCase):
    """Parent decision (review finding 3): a masking exception never emits
    raw text - lines carrying an inventory word or a token-format needle are
    withheld and one marker line is appended."""

    TEXT = (
        "ok line\n"
        "password=%s\n"
        "ACCESS-KEY: x\n"
        "using ghp_abc now\n"
        "Authorization: Bearer x\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEow\n"
        "-----END RSA PRIVATE KEY-----\n"
        "tail\n" % S
    )

    def _boom(self, *_a, **_k):
        raise RuntimeError("boom")

    def test_redact_text_falls_back_to_line_drop(self):
        from unittest import mock

        with mock.patch.object(redaction, "_mask", self._boom):
            out = redaction.redact_text(self.TEXT)
        self.assertEqual(
            out, "ok line\ntail\n[actx] masking failed; 7 lines withheld\n"
        )

    def test_no_trailing_newline_and_nothing_withheld(self):
        from unittest import mock

        with mock.patch.object(redaction, "_mask", self._boom):
            self.assertEqual(
                redaction.redact_text("a\nb"),
                "a\nb\n[actx] masking failed; 0 lines withheld\n",
            )
            self.assertEqual(
                redaction.redact_text("x token=1"),
                "[actx] masking failed; 1 lines withheld\n",
            )

    def test_fallback_failure_withholds_everything(self):
        from unittest import mock

        with mock.patch.object(redaction, "_mask", self._boom), mock.patch.object(
            redaction, "_withheld_line", self._boom
        ):
            self.assertEqual(
                redaction.redact_text("plain\n"),
                "[actx] masking failed; all lines withheld\n",
            )


# --- TK-61 review fixes 2: nested escape levels (red on 7e3e2ac) ------------
# A document embedded n times (json.dumps n times) puts its keys at escape
# depth n: `"` at depth 0, `\"` at 1, `\\\"` at 2, 2^n-1 backslashes at n.


def _nest(text, depth):
    for _ in range(depth):
        text = json.dumps(text, ensure_ascii=False)
    return text


def _unnest(test, text, depth):
    """json.loads `depth` times; each level must parse to a string."""
    for level in range(depth):
        try:
            text = json.loads(text)
        except ValueError as exc:
            test.fail("level %d does not parse: %s" % (level, exc))
        test.assertIsInstance(text, str)
    return text


def _masked_dump(obj, **kw):
    return json.dumps(obj, ensure_ascii=False, **kw)


# (depth-0 document, masked at depth 0, masked at depth >= 1 or None = same)
NESTED_ROWS = (
    (json.dumps({"password": S}), _masked_dump({"password": M}), None),
    (json.dumps({"password": 12, "a": 1}), _masked_dump({"password": M, "a": 1}), None),
    (json.dumps({"token": None}), _masked_dump({"token": M}), None),
    (
        json.dumps({"password": {"u": S, "l": [1, {"p": S}]}, "z": 2}),
        _masked_dump({"password": M, "z": 2}),
        None,
    ),
    (
        json.dumps({"password": {"u": 'a}"]b\\', "v": "[c"}, "k": 1}),
        _masked_dump({"password": M, "k": 1}),
        None,
    ),
    (
        json.dumps({"password": 'a\\"b\\\\' + S, "k": "x\\"}),
        _masked_dump({"password": M, "k": "x\\"}),
        None,
    ),
    (
        json.dumps({"a": 1, "password": S, "n": [1, 2]}, indent=2),
        _masked_dump({"a": 1, "password": M, "n": [1, 2]}, indent=2),
        None,
    ),
    (
        json.dumps({"credentials": {"u": S}, "tokens": [S]}, indent=2),
        _masked_dump({"credentials": M, "tokens": M}, indent=2),
        None,
    ),
    (
        json.dumps({"s": json.dumps({"password": S})}),
        _masked_dump({"s": _masked_dump({"password": M})}),
        None,
    ),
    (
        json.dumps({"msg": "x password: %s y" % S, "k": 1}),
        _masked_dump({"msg": "x password: %s" % M, "k": 1}),
        None,
    ),
    (
        json.dumps({"msg": "password=%s user=bob" % S}),
        _masked_dump({"msg": "password=%s user=bob" % M}),
        None,
    ),
    # '...' keys inside: a literal/container is `"‹masked›"` at depth 0 and
    # `'‹masked›'` inside an enclosing string
    ("{'password': '%s', 'n': 1}" % S, "{'password': '%s', 'n': 1}" % M, None),
    ("{'password': 12}", "{'password': %s}" % QM, "{'password': '%s'}" % M),
    (
        "{'password': {'u': '%s'}, 'n': 1}" % S,
        "{'password': %s, 'n': 1}" % QM,
        "{'password': '%s', 'n': 1}" % M,
    ),
    (
        json.dumps({"s": "{'password': '%s'}" % S}),
        _masked_dump({"s": "{'password': '%s'}" % M}),
        None,
    ),
)


class NestedEscapeLevelTests(unittest.TestCase):
    def test_rows_every_depth_round_trips(self):
        for doc, masked0, masked_deep in NESTED_ROWS:
            for depth in range(5):
                raw = _nest(doc, depth)
                expected = masked0 if depth == 0 or masked_deep is None else masked_deep
                with self.subTest(doc=doc, depth=depth):
                    out = redaction.redact_text(raw)
                    self.assertNotIn(S, out)
                    self.assertEqual(out, _nest(expected, depth))
                    inner = _unnest(self, out, depth)
                    self.assertEqual(inner, expected)
                    if _parses(doc):
                        self.assertTrue(_parses(inner), inner)
                    self.assertEqual(redaction.redact_text(out), out)

    def test_parent_rows(self):
        # json.dumps^3 / ^4 of {"password": V}, and indent=2 at every level
        # (the newlines become `\n`, `\\n`, `\\\\n` escapes)
        for depth in (3, 4):
            for indent in (None, 2):
                raw = json.dumps({"password": S, "a": 1}, indent=indent)
                for _ in range(depth - 1):
                    raw = json.dumps(raw, indent=indent)
                with self.subTest(depth=depth, indent=indent):
                    out = redaction.redact_text(raw)
                    self.assertNotIn(S, out)
                    inner = _unnest(self, out, depth - 1)
                    self.assertEqual(json.loads(inner), {"password": M, "a": 1})

    def test_generated_depth_sweep(self):
        keys = ("password", "PGPASSWORD", "api-key", "awsSecretAccessKey", "id_token",
                "tokenizer", "max_tokens", "secret_name", "username")
        checked = 0
        for key in keys:
            secret = plan_is_secret(key)
            for template, oracle in DIFF_FORMS:
                line = template.format(k=key)
                expected = oracle.format(k=key) if secret else line
                for depth in range(5):
                    raw = _nest(line, depth)
                    out = redaction.redact_text(raw)
                    checked += 1
                    with self.subTest(line=line, depth=depth):
                        if not secret:
                            self.assertEqual(out, raw)
                        self.assertEqual(_unnest(self, out, depth), expected)
                        for value in (V, V2) if secret else ():
                            self.assertNotIn(value, out)
            for template in EMBED_EXTRA_FORMS:
                line = template.format(k=key)
                decoded = []
                for depth in range(5):
                    out = redaction.redact_text(_nest(line, depth))
                    checked += 1
                    with self.subTest(line=line, depth=depth):
                        if secret:
                            self.assertNotIn(V, out)
                        decoded.append(_unnest(self, out, depth))
                with self.subTest(line=line):
                    # depth >= 1 agree ('...' literals are quoted as '...'
                    # inside an enclosing string, as "..." at depth 0)
                    self.assertEqual(decoded[2:], [decoded[1]] * 3)
                    if not secret:
                        self.assertEqual(decoded, [line] * 5)
        self.assertGreater(checked, 900)


class _FreshScan(redaction._Scan):
    """Every scanner call rescans (no reuse): the reference for the memos."""

    def eol(self, i):
        return redaction._eol(self.text, i)

    def comment(self, i, eol):
        match = redaction._COMMENT_RE.search(self.text, i, eol)
        return None if match is None else match.start()

    def deep_end(self, i, quote, depth):
        return redaction._deep_string_end(self.text, i, quote, depth)

    def run_end(self, i, stop):
        return redaction._run_end(self.text, i, stop)

    def resolve(self, spans):
        out = []
        for span in spans:
            if span[1] is None:
                v, depth, mask, tail = self._containers[span[3]]
                end = redaction._bracket_end(self.text, v, depth)
                if tail is not None:
                    end = redaction._run_end(self.text, end, tail)
                span = (v, end, mask)
            out.append(span)
        return out


class _CountingPattern:
    def __init__(self, pattern):
        self.pattern = pattern
        self.calls = 0

    def search(self, *args):
        self.calls += 1
        return self.pattern.search(*args)


class SharedRegionLinearTests(unittest.TestCase):
    """Many hits inside one unbounded value region (one long line, an
    unclosed string, run or container) reuse one scan: scanner calls grow
    with the hits, not hits x region (counted calls, not wall-clock), and
    the output equals a fresh scan per hit."""

    N = 300
    BS = "\\"

    def cases(self):
        n, bs = self.N, self.BS
        return (
            ("password: v x " * n, "password: %s " % M, ("_eol", "_COMMENT_RE")),
            ('"' + "password: v x " * n, '"password: %s ' % M, ("_deep_string_end",)),
            ((bs * 3 + '"password: v x' + bs * 3 + '" ' + bs + '"token: y' + bs + '" ') * n,
             None, ("_eol", "_COMMENT_RE")),
            ("password=" * n, "password=" + M, ("_run_end",)),
            ("--token=" * n, "--token=" + M, ("_run_end",)),
            ('password={"x" ' * n, "password=" + M, ("_string_end",)),
            ('"password": [ "x" ' * n, '"password": ' + QM, ("_string_end",)),
            ("password={" * n + "}" * n, "password=" + M, ("_string_end",)),
        )

    def test_scanner_calls_linear_in_hits(self):
        from unittest import mock

        for text, expected, names in self.cases():
            for name in names:
                with self.subTest(text=text[:40], name=name):
                    if name == "_COMMENT_RE":
                        spy = _CountingPattern(redaction._COMMENT_RE)
                        with mock.patch.object(redaction, name, spy):
                            out = redaction.redact_text(text)
                        calls = spy.calls
                    else:
                        real = getattr(redaction, name)
                        with mock.patch.object(redaction, name, side_effect=real) as spy:
                            out = redaction.redact_text(text)
                        calls = spy.call_count
                    if expected is not None:
                        self.assertEqual(out, expected)
                    # A fresh scan per hit: N region-long _eol / comment /
                    # _deep_string_end / _run_end calls, and one _string_end
                    # per string per container scan (~N^2/2). Reused: a
                    # few region scans; _string_end once per string (plus
                    # once per quoted-key candidate).
                    limit = 3 * self.N if name == "_string_end" else 4
                    self.assertLessEqual(calls, limit, name)

    def test_memo_output_equals_fresh_scans(self):
        import random
        from unittest import mock

        bs = self.BS
        tokens = (
            "password", "token", "--token", "secret", "x", "1", "null", "=", ": ",
            ":", '":', " ", "\t", ",", '"', "'", bs, bs * 2, bs + '"',
            bs * 3 + '"', bs * 7 + '"', bs + "'", bs + "n", "{", "[", "}", "]",
            " #", "\n", "b'", "=>",
        )
        rng = random.Random(7)
        texts = [unit * 40 for unit in (case[0][:40] for case in self.cases())]
        for _ in range(3000):
            text = "".join(rng.choice(tokens) for _ in range(rng.randint(3, 60)))
            k = rng.random()
            if k < 0.15:
                text = json.dumps(text)
            elif k < 0.25:
                text = json.dumps(json.dumps(text))
            elif k < 0.3:
                text *= rng.randint(2, 6)
            texts.append(text)
        for text in texts:
            memo = redaction.redact_text(text)
            with mock.patch.object(redaction, "_Scan", _FreshScan):
                fresh = redaction.redact_text(text)
            self.assertEqual(memo, fresh, repr(text))


class ExclusionRuleTests(unittest.TestCase):
    ROWS = (
        # (key, rule freeing it or None when secret)
        ("tokenizer", "a"), ("Tokenizers", "a"), ("detokenize", "a"),
        ("tokenizer_path", "b"), ("tokenize_key", None), ("tokenizer_auth", None),
        ("token_count", "b"), ("token_type", "b"), ("secret_name", "b"),
        ("password_file", "b"), ("max_password_len", "b"), ("secret_url", None),
        ("token_url", None),
        ("max_tokens", "c"), ("n_tokens", "c"), ("input_tokens", "c"),
        ("cached_tokens", "c"), ("cache_read_tokens", "c"), ("maxTokens", "c"),
        ("cached_token", None), ("cache_token", None), ("output_token", None),
        ("tokens", None), ("max_tokens_secret", None),
        ("NextToken", "d"), ("nextPageToken", "d"), ("next_page_token", "d"),
        ("page_token", "d"), ("CONTINUATION_TOKEN", "d"),
        ("id_token", None), ("PWD", None), ("OLDPWD", None), ("Pwd", None),
        ("PGPASSWORD", None), ("REGISTRY_CREDENTIALS", None),
    )

    def test_rows(self):
        for key, rule in self.ROWS:
            with self.subTest(key=key):
                self.assertEqual(plan_exclusion(key), rule)
                self.assertEqual(redaction._is_secret_key(key), rule is None)


if __name__ == "__main__":
    unittest.main()
