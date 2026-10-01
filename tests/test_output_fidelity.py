"""TK-61 C3: output classes, dispatch and fidelity, generated from data.

Red on cdd4f68 (C2), green after C3. In-process `cli.main` with a mocked
`subprocess.run`; no real program runs.

1. Fidelity: every argv of the union of HEAD_SPECS verb paths (generated
   family leaves included), every rewritten entry of typical_usage.json and
   rewrite_corpus.json, and the run-prefix products (`uv run <content head>`,
   `xcrun simctl ...`) is dispatched at mocked rc 0 and rc 1 with a
   synthetic raw (2500 lines, a 5000-char line, repeats, tabs, trailing
   spaces, CRLF, ANSI, unicode; an invalid UTF-8 byte on bytes-mode paths):
   content -> stdout/stderr bytes == raw; log -> raw minus `[xN]` collapse
   and ANSI; summary -> non-empty stdout; any cut or omitted listing entry ->
   a tee whose JSON stdout == redact_text(raw stdout); rc == mocked rc.
2. Dispatch, rewrite and hang guards.
2a. Class-table guard: the published leaf -> class table below.
3. JSON rule: one-line JSON through cloud summary leaves and aws prints
   exactly redact_text(raw).
Plus: runner.print_raw / raw_fallback mask secret values (parent decision
"secrets always masked").
"""

import ast
import io
import json
import os
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

from actx_lib import (
    cli,
    cli_families,
    hang_policy,
    redaction,
    rewrite_spec,
    rewriter,
    runner,
    tracking,
)
from actx_lib.filters import REGISTRY

TESTS = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(TESTS, "fixtures")


def _synthetic_text():
    lines = ["line %04d\tcol  " % i for i in range(2500)]
    lines[10:13] = ["same"] * 3
    lines[20] = "crlf line\r"
    lines.append("x" * 5000)
    lines.append("\x1b[31mred\x1b[0m ünïcödé")
    return "\n".join(lines) + "\n"


RAW_TEXT = _synthetic_text()
RAW_BYTES = RAW_TEXT.encode("utf-8") + b"bad byte \xff here\n"
ERR_TEXT = "stderr note\twith tab  \n"
ERR_BYTES = ERR_TEXT.encode("utf-8") + b"bad \xfe\n"

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_COLLAPSED = re.compile(r"(.*)  \[×(\d+)\]", re.S)
_TEE_PATH = re.compile(r"full output: ([^\]\n]+)\]")
_LISTING = {"ls", "gls", "find", "tree"}

# --- 2a: the published leaf -> class table ---------------------------------
# Every HEAD_SPECS verb path resolves to the class of its longest prefix
# listed here; an unlisted head defaults to summary. Literal data, written
# independently of rewrite_spec/cli_families (no flag-dependent classes).
PUBLISHED_CLASSES = {
    # content heads
    "cat": "content", "head": "content", "tail": "content",
    "sort": "content", "uniq": "content", "wc": "content",
    "rg": "content", "grep": "content", "redis-cli": "content",
    # content leaves of summary heads
    "git diff": "content", "git show": "content", "git blame": "content",
    "git stash list": "content",
    "gh pr view": "content", "gh pr diff": "content",
    "gh issue view": "content", "gh run view": "content",
    "gh repo view": "content", "gh release view": "content",
    "gh workflow view": "content",
    "docker inspect": "content",
    "kubectl get": "content", "kubectl describe": "content",
    "helm template": "content", "helm get metadata": "content",
    "helm show values": "content", "helm show chart": "content",
    "terraform plan": "content", "terraform show": "content",
    "terraform graph": "content", "terraform output": "content",
    "bq show": "content", "bq head": "content",
    "pod spec cat": "content",
    # one named object's data: borderline -> content (TK-61 C3 fix)
    "npm view": "content", "npm info": "content", "npm show": "content",
    "npm explain": "content", "npm config get": "content",
    "pnpm why": "content",
    "pip show": "content", "pip inspect": "content",
    "pip config get": "content",
    "cargo metadata": "content",
    "pod spec which": "content",
    # the log class: exactly these four
    "docker logs": "log", "docker compose logs": "log",
    "kubectl logs": "log", "vercel logs": "log",
}


def _published(path):
    for n in range(len(path), 0, -1):
        cls = PUBLISHED_CLASSES.get(" ".join(path[:n]))
        if cls is not None:
            return cls
    return "summary"


def _walk(level, path, out):
    out.append(path)
    for tok, child in (level["verbs"] or {}).items():
        _walk(child, path + [tok], out)


def spec_paths(include_inner_only=False):
    out = []
    for head, root in rewrite_spec.HEAD_SPECS.items():
        if root is None:
            continue
        if head in rewrite_spec.INNER_ONLY_HEADS and not include_inner_only:
            continue
        _walk(root, [head], out)
    return out


def corpus_argvs():
    out = []
    for name in ("typical_usage.json", "rewrite_corpus.json"):
        with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
            for rewritten in json.load(handle).values():
                if rewritten is None:
                    continue
                tokens = shlex.split(rewritten)
                assert tokens[0] == "actx", rewritten
                out.append(tokens[1:])
    return out


def run_prefix_argvs():
    out = []
    for head, root in rewrite_spec.HEAD_SPECS.items():
        if root is not None and root["output"] == "content":
            out.append(["uv", "run", head, "x"])
    for name, spec in cli_families.RUN_PREFIXES.items():
        tool = spec.get("only_tool")
        if tool:
            for path in spec_paths(include_inner_only=True):
                if path[0] == tool:
                    out.append([name] + path)
    return out


def enumeration():
    seen = set()
    out = []
    for argv in spec_paths() + corpus_argvs() + run_prefix_argvs():
        key = tuple(argv)
        if key not in seen:
            seen.add(key)
            out.append(argv)
    return out


def _expand_collapse(text):
    out = []
    for line in text.split("\n"):
        match = _COLLAPSED.fullmatch(line)
        if match:
            out.extend([match.group(1)] * int(match.group(2)))
        else:
            out.append(line)
    return "\n".join(out)


class _Harness(unittest.TestCase):
    def setUp(self):
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        env = mock.patch.dict(
            os.environ, {"HOME": home.name, "ACTX_TRACKING": "0"}
        )
        env.start()
        self.addCleanup(env.stop)
        # cli.main sets tracking's module state from the loaded config;
        # restore it so later test modules see the default again.
        for name in ("_ENABLED", "_RETENTION_DAYS"):
            patcher = mock.patch.object(tracking, name, getattr(tracking, name))
            patcher.start()
            self.addCleanup(patcher.stop)
        cwd = os.getcwd()
        os.chdir(work.name)
        self.addCleanup(os.chdir, cwd)
        self.tee_dir = os.path.join(home.name, "tee")
        path = os.path.join(home.name, ".config", "actx", "config.json")
        os.makedirs(os.path.dirname(path))
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({
                "tee": {"enabled": False, "mode": "failures",
                        "dir": self.tee_dir, "min_bytes": 0},
                "truncate": {"max_lines": 500, "max_line_chars": 300},
                "tracking": {"enabled": False, "history_days": 90},
            }, handle)

    def dispatch(self, argv, rc=0, text=RAW_TEXT, data=RAW_BYTES,
                 err_text=ERR_TEXT, err_data=ERR_BYTES, raise_exc=None):
        """cli.main(['actx'] + argv) with subprocess.run mocked: text-mode
        calls get str streams, bytes-mode calls bytes. Returns (rc, stdout
        bytes, stderr bytes, executed argvs)."""
        calls = []

        def fake(cmd, *args, **kwargs):
            calls.append(list(cmd))
            if raise_exc is not None:
                raise raise_exc
            if kwargs.get("text"):
                return subprocess.CompletedProcess(cmd, rc, text, err_text)
            return subprocess.CompletedProcess(cmd, rc, data, err_data)

        out_b, err_b = io.BytesIO(), io.BytesIO()
        out = io.TextIOWrapper(out_b, encoding="utf-8", newline="")
        err = io.TextIOWrapper(err_b, encoding="utf-8", newline="")
        with mock.patch("subprocess.run", side_effect=fake), mock.patch(
            "sys.stdout", out
        ), mock.patch("sys.stderr", err):
            code = cli.main(["actx"] + list(argv))
            out.flush()
            err.flush()
        result = (code, out_b.getvalue(), err_b.getvalue(), calls)
        out.detach()
        err.detach()
        return result


class FidelityTests(_Harness):
    """Test 1: every enumerated argv, mocked rc 0 and rc 1."""

    def test_raw_is_secret_free(self):
        # The byte-equality oracles below assume masking is the identity.
        self.assertEqual(redaction.redact_text(RAW_TEXT), RAW_TEXT)
        self.assertEqual(redaction.redact_text(ERR_TEXT), ERR_TEXT)

    def test_enumeration_covers_every_source(self):
        argvs = {tuple(a) for a in enumeration()}
        for source in (spec_paths(), corpus_argvs(), run_prefix_argvs()):
            self.assertTrue(source)
            self.assertTrue({tuple(a) for a in source} <= argvs)
        self.assertIn(("uv", "run", "cat", "x"), argvs)
        self.assertIn(("xcrun", "simctl", "list"), argvs)
        self.assertNotIn(("simctl",), argvs)

    def _check_tee(self, argv, out, err):
        text = (out + err).decode("utf-8", "replace")
        paths = set(_TEE_PATH.findall(text))
        cut = "...[truncated:" in text or "...(truncated)" in text
        omitted = False
        if argv[0] in _LISTING or argv[:2] == ["git", "status"]:
            shown = _ANSI.sub("", out.decode("utf-8", "replace"))
            omitted = any(
                line.strip() and _ANSI.sub("", line).strip() not in shown
                for line in RAW_TEXT.split("\n")
            )
        if cut or omitted:
            self.assertTrue(paths, "cut/omitted without a tee path: %r" % argv)
        for path in paths:
            self.assertTrue(os.path.isfile(path), path)
            with open(path, encoding="utf-8") as handle:
                record = json.load(handle)
            self.assertEqual(
                record["stdout"], redaction.redact_text(RAW_TEXT), path
            )

    def test_every_argv_keeps_its_class_contract(self):
        expected_log = _expand_collapse(_ANSI.sub("", RAW_TEXT))
        for argv in enumeration():
            cls = rewriter.output_class(argv)
            with self.subTest(argv=argv):
                self.assertIn(cls, ("content", "log", "summary"))
            for rc in (0, 1):
                with self.subTest(argv=argv, rc=rc, cls=cls):
                    code, out, err, calls = self.dispatch(argv, rc)
                    if not calls:
                        # No execution: a never-wrap refusal, or a summary
                        # computed without a program (bare tree walk).
                        if code == runner.NEVER_WRAP_EXIT_CODE:
                            self.assertEqual(
                                hang_policy.classify(argv), "never_wrap"
                            )
                        else:
                            self.assertEqual(cls, "summary")
                            self.assertTrue(out.strip())
                        continue
                    self.assertEqual(code, rc)
                    if cls == "content":
                        self.assertEqual(calls, [argv])
                        self.assertEqual(out, RAW_BYTES)
                        self.assertEqual(err, ERR_BYTES)
                    elif cls == "log":
                        self.assertEqual(calls, [argv])
                        shown = out.decode("utf-8")
                        self.assertIn("same  [×3]", shown)
                        self.assertEqual(_expand_collapse(shown), expected_log)
                        self.assertEqual(err, ERR_TEXT.encode("utf-8"))
                    else:
                        self.assertTrue(out.strip(), "empty summary stdout")
                        self._check_tee(argv, out, err)


class ClassTableTests(unittest.TestCase):
    """Test 2a."""

    def test_every_spec_path_matches_the_published_table(self):
        paths = spec_paths(include_inner_only=True)
        self.assertGreater(len(paths), 200)
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(rewriter.output_class(path), _published(path))

    def test_published_entries_exist_in_the_spec(self):
        known = {" ".join(p) for p in spec_paths(include_inner_only=True)}
        for key in PUBLISHED_CLASSES:
            with self.subTest(key=key):
                self.assertIn(key, known)

    def test_log_class_is_exactly_four_leaves(self):
        logs = sorted(
            " ".join(p) for p in spec_paths(include_inner_only=True)
            if rewriter.output_class(p) == "log"
        )
        self.assertEqual(
            logs,
            ["docker compose logs", "docker logs", "kubectl logs",
             "vercel logs"],
        )

    def test_kubectl_get_is_content_whatever_the_output_flag(self):
        for flags in (
            [], ["-o", "json"], ["-o", "yaml"], ["--output=json"],
            ["--output", "yaml"], ["-ojson"], ["-o", "wide"],
            ["-o", "jsonpath={.items[*].metadata.name}"],
        ):
            for prefix in ([], ["-n", "prod"], ["--context=x"]):
                argv = ["kubectl"] + prefix + ["get", "pods"] + flags
                with self.subTest(argv=argv):
                    self.assertEqual(rewriter.output_class(argv), "content")

    def test_every_head_node_declares_its_class(self):
        for head, root in rewrite_spec.HEAD_SPECS.items():
            with self.subTest(head=head):
                self.assertIn(root["output"], ("content", "log", "summary"))

    def test_family_output_verbs_name_real_verbs(self):
        for name, fam in cli_families.FAMILIES.items():
            self.assertIn(fam.get("output"), (None, "content", "summary"))
            for path, cls in (fam.get("output_verbs") or {}).items():
                with self.subTest(family=name, path=path):
                    node = rewrite_spec.HEAD_SPECS[name]
                    for tok in path:
                        node = (node["verbs"] or {}).get(tok)
                        self.assertIsNotNone(node)
                    self.assertEqual(node["output"], cls)

    def test_registry_only_heads(self):
        for argv, cls in (
            (["aws", "sts", "get-caller-identity"], "summary"),
            (["read", "f"], "summary"),
            (["smart", "f"], "summary"),
            (["uv", "run", "rg", "x"], "content"),
            (["uv", "run", "pytest"], "summary"),
            (["uv", "pip", "install", "x"], "summary"),
            (["xcrun", "simctl", "list"], "summary"),
            (["/usr/bin/xcrun", "simctl", "list"], "summary"),
            (["nosuchtool", "x"], None),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(rewriter.output_class(argv), cls)


class DispatchGuardTests(_Harness):
    """Test 2: dispatch, rewrite and hang guards."""

    def _guard_argvs(self):
        out = []
        for path in spec_paths():
            out.append(path)
            if "/" not in path[0]:
                out.append(["/usr/bin/" + path[0]] + path[1:])
        for head in REGISTRY:
            out.append([head])
        out.append(["./gradlew", "build"])
        return out

    def test_no_known_head_is_an_unknown_command(self):
        for argv in self._guard_argvs():
            with self.subTest(argv=argv):
                code, out, err, calls = self.dispatch(argv, 0)
                self.assertNotIn(b"unknown command", err)
                cls = rewriter.output_class(argv)
                self.assertIsNotNone(cls)
                path_written = (
                    "/" in argv[0]
                    and argv[0] not in cli_families.LITERAL_HEAD_KEYS
                )
                if calls and (cls in ("content", "log") or path_written):
                    self.assertEqual(calls[0], argv)

    def test_missing_binary_is_127(self):
        for argv in (
            ["cat", "f"],
            ["/bin/cat", "f"],
            ["git", "diff"],
            ["uv", "run", "rg", "x"],
            ["docker", "logs", "c"],
            ["/usr/bin/docker", "ps"],
            ["/usr/local/bin/git", "status"],
            ["simctl", "list"],
        ):
            with self.subTest(argv=argv):
                code, out, err, calls = self.dispatch(
                    argv, raise_exc=FileNotFoundError(2, "No such file")
                )
                self.assertEqual(code, 127)
                self.assertEqual(calls, [argv])

    def test_class_resolution_error_prints_masked_raw(self):
        data = b"M  a.txt\npassword=s3cret\n"
        with mock.patch(
            "actx_lib.rewriter.output_class", side_effect=RuntimeError("x")
        ):
            code, out, err, calls = self.dispatch(
                ["git", "status"], 1, data=data, err_data=b""
            )
        self.assertEqual(code, 1)
        self.assertEqual(calls, [["git", "status"]])
        self.assertEqual(
            out,
            redaction.redact_text(data.decode("utf-8")).encode("utf-8"),
        )
        self.assertNotIn(b"s3cret", out)

    def test_unknown_head_is_rc_1(self):
        code, out, err, calls = self.dispatch(["nosuchtool", "x"])
        self.assertEqual(code, 1)
        self.assertIn(b"unknown command: nosuchtool", err)
        self.assertEqual(calls, [])

    def test_manual_simctl_runs_lossless(self):
        with mock.patch.object(
            runner, "run_lossless", wraps=runner.run_lossless
        ) as lossless:
            code, out, err, calls = self.dispatch(["simctl", "list"], 0)
        self.assertEqual(code, 0)
        self.assertEqual(lossless.call_args.args[0], ["simctl", "list"])
        self.assertEqual(calls, [["simctl", "list"]])

    def test_run_failures_green_pytest_is_silent(self):
        code, out, err, calls = self.dispatch(
            ["run", "--failures", "pytest"], 0,
            text="....\n4 passed in 0.01s\n", err_text="",
        )
        self.assertEqual(code, 0)
        self.assertEqual(out, b"")

    def test_custom_head_named_like_a_class_head_is_reserved(self):
        path = os.path.join(
            os.environ["HOME"], ".config", "actx", "config.json"
        )
        with open(path, encoding="utf-8") as handle:
            config = json.load(handle)
        config["custom_heads"] = ["cat", "mytool"]
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)
        code, out, err, calls = self.dispatch(["mytool", "x"], 0)
        self.assertEqual(code, 0)
        self.assertIn(b"ignoring reserved custom head: cat", err)


class RewriteGuardTests(unittest.TestCase):
    def test_path_written_run_prefix_heads_are_refused(self):
        for command in (
            "/tmp/x/uv run cat f",
            "./uv run cat f",
            "bin/uv run cat f",
            "/usr/bin/xcrun simctl list",
            "/usr/local/bin/uv run pytest",
        ):
            with self.subTest(command=command):
                self.assertIsNone(rewriter.rewrite(command))

    def test_bare_simctl_is_refused(self):
        for command in ("simctl list", "simctl list devices", "simctl"):
            with self.subTest(command=command):
                self.assertIsNone(rewriter.rewrite(command))

    def test_bare_run_prefixes_still_rewrite(self):
        self.assertEqual(rewriter.rewrite("uv run cat f"), "actx uv run cat f")
        self.assertEqual(
            rewriter.rewrite("xcrun simctl list"), "actx xcrun simctl list"
        )
        self.assertIn("simctl", rewrite_spec.HEAD_SPECS)


def _hang_policy_cases():
    """Every argv literal passed to a `classify(...)` call in
    tests/test_hang_policy.py (list literals and shlex.split strings)."""
    with open(os.path.join(TESTS, "test_hang_policy.py"), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and node.args):
            continue
        func = node.func
        name = getattr(func, "attr", None) or getattr(func, "id", None)
        if name != "classify":
            continue
        arg = node.args[0]
        try:
            value = ast.literal_eval(arg)
        except ValueError:
            continue
        if isinstance(value, str):
            value = shlex.split(value)
        if isinstance(value, list) and value and all(
            isinstance(tok, str) for tok in value
        ):
            out.append(value)
    return out


class HangGuardTests(unittest.TestCase):
    def test_path_written_head_classifies_like_the_bare_head(self):
        cases = [
            argv for argv in _hang_policy_cases()
            if hang_policy.classify(argv) == "never_wrap"
        ]
        self.assertGreater(len(cases), 20)
        for argv in cases:
            if "/" in argv[0]:
                continue
            path_argv = ["/usr/bin/" + argv[0]] + argv[1:]
            with self.subTest(argv=path_argv):
                self.assertEqual(hang_policy.classify(path_argv), "never_wrap")


def _json_raw():
    items = ", ".join(
        '{"id": %d, "label": "значение-%d", "id": "dup-%d"}' % (i, i, i)
        for i in range(80)
    )
    raw = (
        '{"name": "ünïcödé", "name": "duplicate", "password": "s3cret", '
        '"items": [%s], "tail": "%s"}\n' % (items, "z" * 2000)
    )
    assert len(raw) > 5000 and "\n" not in raw[:-1]
    json.loads(raw)
    return raw


class JsonRuleTests(_Harness):
    """Test 3 JSON rule: one-line JSON on summary/cloud leaves prints
    exactly redact_text(raw) - fails if json.dumps re-serialises it."""

    def _argvs(self):
        out = [["aws", "sts", "get-caller-identity"]]
        for name, fam in cli_families.FAMILIES.items():
            if REGISTRY.get(name) is None or name in (
                "docker", "kubectl", "helm", "gh"
            ):
                continue
            for path in spec_paths():
                if path[0] == name and len(path) > 1 and (
                    rewriter.output_class(path) == "summary"
                ):
                    out.append(path)
        return out

    def test_json_printed_as_masked_raw_text(self):
        raw = _json_raw()
        expected = redaction.redact_text(raw).encode("utf-8")
        self.assertNotIn(b"s3cret", expected)
        argvs = self._argvs()
        self.assertGreater(len(argvs), 10)
        for argv in argvs:
            for rc in (0, 1):
                with self.subTest(argv=argv, rc=rc):
                    code, out, err, calls = self.dispatch(
                        argv, rc, text=raw, err_text=""
                    )
                    self.assertEqual(code, rc)
                    self.assertEqual(out, expected)


class PrintRawMaskingTests(unittest.TestCase):
    """Parent decision: secrets always masked - the raw fallback of a failed
    or empty compactor prints the result with secret values masked, every
    other byte as the command wrote it."""

    def _capture(self, fn, result):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            rc = fn(result)
        return rc, out.getvalue(), err.getvalue()

    def test_print_raw_masks_values(self):
        result = subprocess.CompletedProcess(
            ["x"], 0, "a\tb  \npassword=s3cret\n", "token=abc123def\nplain\n"
        )
        _, out, err = self._capture(runner.print_raw, result)
        self.assertEqual(out, "a\tb  \npassword=‹masked›\n")
        self.assertEqual(err, "token=‹masked›\nplain\n")

    def test_raw_fallback_masks_values_keeps_rc(self):
        result = subprocess.CompletedProcess(
            ["x"], 3, "ok\napi_key: s3cret\n", ""
        )
        rc, out, err = self._capture(runner.raw_fallback, result)
        self.assertEqual(rc, 3)
        self.assertEqual(out, "ok\napi_key: ‹masked›\n")
        self.assertEqual(err, "")

    def test_masking_error_fails_open_to_raw(self):
        result = subprocess.CompletedProcess(["x"], 0, "password=s3cret\n", "")
        with mock.patch(
            "actx_lib.redaction.redact_text", side_effect=RuntimeError("x")
        ):
            _, out, _ = self._capture(runner.print_raw, result)
        self.assertEqual(out, "password=s3cret\n")


# ---------------------------------------------------------------------
# TK-61 C3 fix: red on 6f22533, green after.
# ---------------------------------------------------------------------

SECRET = b"s3cret"
SECRET_DATA = b"ok \xff line\npassword=s3cret\n"
SECRET_ERR = b"token=abc123def\n"
_PYTEST_FAILURE = (
    "============================= test session starts ==============\n"
    "collected 1 item\n\n"
    "test_x.py F                                                [100%]\n\n"
    "=================================== FAILURES ===================\n"
    "___________________________________ test_x ____________________\n\n"
    "    def test_x():\n"
    ">       assert False, \"password=s3cret\"\n"
    "E       AssertionError: password=s3cret\n\n"
    "test_x.py:2: AssertionError\n"
    "=========================== short test summary info ============\n"
    "FAILED test_x.py::test_x - AssertionError: password=s3cret\n"
    "============================== 1 failed in 0.01s ===============\n"
)


def _mask(data):
    """The bytes a masking path must print: redact_text over the
    surrogateescape text, every other byte unchanged."""
    text = data.decode("utf-8", "surrogateescape")
    return redaction.redact_text(text).encode("utf-8", "surrogateescape")


class SecretsAlwaysMaskedTests(_Harness):
    """Owner rule "secrets always masked, no exceptions": every path that
    prints command output masks secret values - the bytes passthrough
    (unknown-flag forms, ls at rc != 0, --raw, the filters' passthrough
    branches) and every summary print site."""

    PASSTHROUGH_FORMS = (
        ["ls", "--color=never"],
        ["ls", "a", "b"],
        ["gls", "-R"],
        ["find", ".", "-print0"],
        ["git", "log", "-p"],
        ["git", "branch"],
        ["git", "rev-parse", "HEAD"],
        ["uv", "pip", "show", "x"],
        ["read", "f.py"],
        ["--raw", "git", "status"],
        ["--raw", "run", "x"],
        ["docker", "--context", "x", "inspect", "c"],
        ["terraform", "-chdir=x", "show"],
        ["npm", "view", "x"],
        ["pip", "show", "x"],
    )

    def test_mask_oracle(self):
        self.assertNotIn(SECRET, _mask(SECRET_DATA))
        self.assertIn(b"\xff", _mask(SECRET_DATA))
        self.assertNotIn(b"abc123def", _mask(SECRET_ERR))

    def test_bytes_paths_mask_values_and_keep_every_other_byte(self):
        for argv in self.PASSTHROUGH_FORMS:
            for rc in (0, 1):
                with self.subTest(argv=argv, rc=rc):
                    code, out, err, calls = self.dispatch(
                        argv, rc, data=SECRET_DATA, err_data=SECRET_ERR
                    )
                    self.assertEqual(code, rc)
                    self.assertEqual(out, _mask(SECRET_DATA))
                    self.assertTrue(err.startswith(_mask(SECRET_ERR)), err)
                    self.assertNotIn(b"abc123def", err)

    def test_bytes_paths_are_identity_without_a_secret(self):
        for argv in self.PASSTHROUGH_FORMS:
            with self.subTest(argv=argv):
                code, out, err, calls = self.dispatch(argv, 0)
                self.assertEqual(code, 0)
                self.assertEqual(out, RAW_BYTES)
                self.assertEqual(err, ERR_BYTES)

    def test_ls_nonzero_exit_masks(self):
        code, out, err, calls = self.dispatch(
            ["ls", "d"], 2, text="", err_text="",
            data=SECRET_DATA, err_data=SECRET_ERR,
        )
        self.assertEqual(code, 2)
        self.assertEqual(calls, [["ls", "-1", "d"], ["ls", "d"]])
        self.assertEqual(out, _mask(SECRET_DATA))
        self.assertNotIn(b"abc123def", err)

    def test_passthrough_masking_error_fails_open(self):
        with mock.patch(
            "actx_lib.redaction.redact_text", side_effect=RuntimeError("x")
        ):
            code, out, err, calls = self.dispatch(
                ["ls", "a", "b"], 0, data=SECRET_DATA, err_data=b""
            )
        self.assertEqual(code, 0)
        self.assertEqual(out, SECRET_DATA)

    def _summary(self, argv, text, rc=0, err_text=""):
        code, out, err, calls = self.dispatch(
            argv, rc, text=text, err_text=err_text
        )
        self.assertNotIn(SECRET, out)
        self.assertNotIn(SECRET, err)
        self.assertIn("‹masked›".encode("utf-8"), out + err)
        return code, out, err, calls

    def test_summary_print_sites_mask(self):
        cases = (
            # git_filter status groups (path names)
            (["git", "status"], "?? password=s3cret\n"),
            # git_filter log (printed as returned)
            (["git", "log"], "abc1234 set password=s3cret\n"),
            # system_filter ls listing
            (["ls"], "password=s3cret\nb\n"),
            # system_filter find groups (> 200 chars: the grouped form)
            (["find", "."], "".join("./d/q%02d\n" % i for i in range(40))
             + "./d/password=s3cret\n"),
            # runner.compacted_result (a compactor keeping raw lines)
            (["pytest"], _PYTEST_FAILURE),
            # runner.run_digest
            (["run", "--digest", "x"], "password=s3cret\n"),
        )
        for argv, text in cases:
            with self.subTest(argv=argv):
                self._summary(argv, text, rc=1 if argv == ["pytest"] else 0)

    def test_run_errors_masks_stderr(self):
        code, out, err, calls = self.dispatch(
            ["run", "--errors", "x"], 1, text="", err_text="password=s3cret\n"
        )
        self.assertEqual(code, 1)
        self.assertNotIn(SECRET, err)
        self.assertIn("password=‹masked›".encode("utf-8"), err)

    def test_listing_with_omitted_entries_masks(self):
        names = ["q%02d" % i for i in range(40)] + ["password=s3cret"]
        self._summary(["ls"], "\n".join(names) + "\n")

    def test_read_level_output_masks(self):
        with open("f.py", "w", encoding="utf-8") as handle:
            handle.write("x = 1\n")
        self._summary(
            ["read", "f.py", "--level", "minimal"],
            "# comment\npassword = 's3cret'\nx = 1\n",
        )

    def test_smart_output_masks(self):
        with open("f.py", "w", encoding="utf-8") as handle:
            handle.write("x = 1\n")
        key = "AKIA" + "IOSFODNN7EXAMPLE"
        code, out, err, calls = self.dispatch(
            ["smart", "f.py"], 0, text="import os\nimport %s\n" % key
        )
        self.assertEqual(code, 0)
        self.assertNotIn(key.encode(), out)
        self.assertIn("‹masked›".encode("utf-8"), out)

    def test_tree_walk_masks(self):
        os.mkdir("d")
        with open(os.path.join("d", "password=s3cret"), "w") as handle:
            handle.write("")
        code, out, err, calls = self.dispatch(["tree", "d"], 0)
        self.assertEqual(code, 0)
        self.assertEqual(calls, [])
        self.assertNotIn(SECRET, out)
        self.assertIn("password=‹masked›".encode("utf-8"), out)


class MissingBinaryTests(_Harness):
    """A missing binary is rc 127 on every ls/gls path and the bytes
    passthrough (the shared _exec_failure mapping)."""

    def test_missing_binary_is_127(self):
        for argv in (
            ["ls"],
            ["gls"],
            ["ls", "d"],
            ["gls", "d"],
            ["ls", "-la"],
            ["ls", "--color=never"],
            ["ls", "a", "b"],
            ["find", ".", "-print0"],
            ["git", "log", "-p"],
            ["--raw", "git", "status"],
        ):
            with self.subTest(argv=argv):
                code, out, err, calls = self.dispatch(
                    argv, raise_exc=FileNotFoundError(2, "No such file")
                )
                self.assertEqual(code, 127)
                self.assertEqual(len(calls), 1)
                self.assertTrue(err.strip())

    def test_not_executable_is_126(self):
        code, out, err, calls = self.dispatch(
            ["ls"], raise_exc=PermissionError(13, "Permission denied")
        )
        self.assertEqual(code, 126)


class GlobalOptionClassTests(_Harness):
    """A manual form with a global option before the verb resolves to the
    verb's class (the lenient class walk); the executed argv is unchanged."""

    CASES = (
        (["docker", "--context", "x", "inspect", "c"], "content"),
        (["docker", "-H", "tcp://h", "inspect", "c"], "content"),
        (["docker", "--context=x", "inspect", "c"], "content"),
        (["docker", "--context", "x", "logs", "c"], "log"),
        (["docker", "compose", "-f", "x.yml", "logs"], "log"),
        (["docker", "compose", "--project-name=p", "logs"], "log"),
        (["terraform", "-chdir=x", "show"], "content"),
        (["terraform", "-chdir=x", "plan"], "content"),
        (["git", "-C", "x", "diff"], "content"),
        (["git", "-c", "a=b", "show", "HEAD"], "content"),
        (["git", "--no-pager", "diff"], "content"),
        (["helm", "--kube-context", "x", "get", "metadata", "r"], "content"),
        (["helm", "-n", "ns", "show", "values", "c"], "content"),
        (["npm", "--prefix", "x", "view", "y"], "content"),
        (["pip", "--isolated", "show", "x"], "content"),
        (["bq", "--format", "json", "show", "d.t"], "content"),
        (["vercel", "--token", "t", "logs", "u"], "log"),
        # still summary: the verb itself is summary, or no verb is reached
        (["docker", "--context", "x", "ps"], "summary"),
        (["git", "-C", "x", "log"], "summary"),
        (["git", "-C", "x", "status"], "summary"),
        (["docker", "--context", "x", "nosuchverb", "inspect"], "summary"),
        (["terraform", "-chdir", "x", "show"], "summary"),
    )

    def test_class_skips_global_options(self):
        for argv, cls in self.CASES:
            with self.subTest(argv=argv):
                self.assertEqual(rewriter.output_class(argv), cls)

    def test_dispatch_follows_the_verb_class(self):
        expected_log = _expand_collapse(_ANSI.sub("", RAW_TEXT))
        for argv, cls in self.CASES:
            if cls == "summary":
                continue
            with self.subTest(argv=argv):
                code, out, err, calls = self.dispatch(argv, 0)
                self.assertEqual(code, 0)
                self.assertEqual(calls, [argv])
                if cls == "content":
                    self.assertEqual(out, RAW_BYTES)
                    self.assertEqual(err, ERR_BYTES)
                else:
                    shown = out.decode("utf-8")
                    self.assertIn("same  [×3]", shown)
                    self.assertEqual(_expand_collapse(shown), expected_log)

    def test_rewrite_decisions_unchanged(self):
        # Class only: the lenient walk never admits a rewrite.
        for argv, _ in self.CASES:
            with self.subTest(argv=argv):
                self.assertIsNone(rewriter.rewrite(shlex.join(argv)))


if __name__ == "__main__":
    unittest.main()
