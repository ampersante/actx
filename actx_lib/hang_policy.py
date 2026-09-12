"""Hang policy: never-wrap registry, timeout classes, prompt detection.

Pure data + argv-token predicates; no execution, no shell. Token equality
only (no substrings), like the tail -f precedent in rewriter.py.
Timeouts come from ~/.config/actx/config.json "timeouts": default_s (600)
for the general class, generous_s (1800) for known long builders; defaults
live in config.DEFAULT_CONFIG.
"""

from actx_lib import cli_families

# Flags that make a command stream forever (exact tokens).
_STREAM_FLAGS = frozenset({"-f", "--follow"})

# kubectl watch flags after get/events (N-F4): `kubectl get pods -w` streams
# until interrupted - a guaranteed 600s hang under the default timeout.
_KUBECTL_WATCH_FLAGS = frozenset({"-w", "--watch", "--watch-only"})

# kubectl object types whose payloads are secret-bearing (N-F3a): base64
# secret values carry no pattern words, so redaction cannot catch them -
# the only safe verdict is never-wrap (exit 125, nothing captured).
_KUBECTL_SECRET_TYPES = frozenset({"secret", "secrets", "configmap", "cm"})

_LOGIN_HEADS = frozenset({
    "wrangler", "railway", "gcloud", "vercel", "netlify", "supabase",
    "flyctl", "fly",
})
# Interactive SQL/warehouse REPLs. TK-43 (N-F15): snowsql/databricks make
# the PRD never-wrap fixation mechanical. sqlite3 leaves the set for the
# db+SQL batch form via the positional-count rule in _is_repl.
_REPL_HEADS = frozenset(
    {"psql", "sqlite3", "duckdb", "mongosh", "snowsql", "databricks"}
)
# run/attach/logs stream; channel/upgrade/downgrade are long interactive
# prompts (TK-42: never-wrap so they cannot stall a wrapped session).
_FLUTTER_STREAM_SUBS = frozenset({
    "run", "attach", "logs", "channel", "upgrade", "downgrade",
})

# Known long builders: generous timeout instead of the default one.
_LONG_OPS = (
    ("flutter", "build"),
    ("xcodebuild",),
    ("cargo", "build"),
    ("go", "build"),
    ("npm", "install"),
    ("npm", "ci"),
    ("pnpm", "install"),
    ("pnpm", "ci"),
    ("pip", "install"),
    ("uv", "pip", "install"),
    ("docker", "build"),
    # Detached `docker compose up -d` (generous via _is_generous). Only
    # covers the flag-less form: compose-level flags (docker compose
    # -f x.yml up -d) defeat a prefix match, so H-F12 adds the dedicated
    # _is_docker_compose_long predicate below for the flag-full forms.
    ("docker", "compose", "up"),
    ("pytest",),
    ("cargo", "test"),
    ("go", "test"),
    ("swift", "build"),
    ("swift", "test"),
    ("pod", "install"),
    ("./gradlew",),
    ("flutter", "pub", "get"),
    ("dart", "pub", "get"),
    ("flutter", "test"),
    ("dart", "test"),
    # Data stack (TK-43): terraform plan walks providers/state and dbt
    # run/test/build compile+execute whole projects - known long builders.
    ("terraform", "plan"),
    ("dbt", "run"),
    ("dbt", "test"),
    ("dbt", "build"),
)

# Interactive confirmation prompts looked for in command output.
_PROMPT_PATTERNS = (
    "[y/n]", "[Y/n]", "[Y/N]",
    "(yes/no)",
    "Proceed?", "Continue?",
    "Press any key",
)


def _is_tail(argv):
    return argv[0] == "tail" and any(
        tok == "-f" or tok == "--follow" or tok.startswith("--follow=")
        for tok in argv[1:]
    )


def _is_kubectl(argv):
    if argv[0] != "kubectl" or len(argv) < 2:
        return False
    rest = argv[1:]
    for idx, tok in enumerate(rest):
        if tok in ("port-forward", "attach"):
            return True
        if tok == "logs":
            return any(t in _STREAM_FLAGS for t in rest[idx + 1:])
    # TK-40: effective verbs (head dropped, -n prod / --namespace=prod /
    # -A skipped via cli_families.effective_verbs - one skip-logic source).
    verbs = cli_families.effective_verbs(argv)
    if not verbs:
        return False
    if verbs[0] in ("get", "events") and any(
        t in _KUBECTL_WATCH_FLAGS for t in verbs[1:]
    ):
        return True  # N-F4: watch streams forever
    if verbs[0] in ("get", "describe") and any(
        t in _KUBECTL_SECRET_TYPES for t in verbs[1:]
    ):
        return True  # N-F3a: base64 secrets dodge pattern redaction
    return False


def _is_docker(argv):
    if argv[0] != "docker" or len(argv) < 2:
        return False
    rest = argv[1:]
    if "compose" in rest:
        # Subcommand may sit behind global flags and compose-level flags
        # (docker --context x compose up, docker compose -f stack.yml up).
        after = rest[rest.index("compose") + 1:]
        if "attach" in after:
            return True
        if "up" in after:
            # detached form terminates; anything else streams
            return not any(t in ("-d", "--detach") for t in after)
        for idx, tok in enumerate(after):
            if tok == "logs":
                # N-F5: RO ("compose", "logs") must not hang the wrapper;
                # plain `compose logs` terminates, -f/--follow streams.
                # Only flags AFTER the logs token count: a compose-level
                # `-f x.yml` before it is a file flag, not --follow.
                return any(t in _STREAM_FLAGS for t in after[idx + 1:])
        return False
    sub = rest[0]
    if sub == "logs":
        return any(t in _STREAM_FLAGS for t in rest[1:])
    if sub == "stats":
        return "--no-stream" not in rest[1:]
    if sub == "attach":
        return True
    return False


def _is_wrangler_tail(argv):
    return argv[0] == "wrangler" and len(argv) >= 2 and argv[1] == "tail"


def _is_cloud_stream(argv):
    """Cloud-family stream/secret verbs (TK-39): skip the family's boolean
    global flags and value-flags-with-values (cli_families.effective_verbs -
    one skip-logic source), then a stream_specs prefix must match exactly.
    Covers `railway logs -f`, `vercel logs --follow`, `helm get values`
    (TK-40: deployed values are the standard home of credentials) and the
    env/variables/secret verbs of every family (Q2: never-wrap, exit 125).
    Logins and `wrangler tail` are kept in their dedicated predicates above -
    the table does not duplicate them."""
    verbs = cli_families.effective_verbs(argv)
    if verbs is None:
        return False
    return any(
        tuple(verbs[: len(seq)]) == seq
        for seq in cli_families.FAMILIES[argv[0]]["stream_specs"]
    )


def _is_jest_vitest_watch(argv):
    """TK-55: jest/vitest watch modes stream forever — never_wrap.
    jest watches only under --watch/--watchAll; vitest watches on bare
    invocation and the `watch` subcommand (`vitest run` is the CI form)."""
    head = argv[0]
    if head == "jest":
        return any(t in ("--watch", "--watchAll", "--watch-all")
                   for t in argv[1:])
    if head == "vitest":
        if len(argv) == 1 or argv[1] == "watch":
            return True
        return "--watch" in argv[1:]
    return False


def _is_watch_fuzz_debug(argv):
    """TK-55: watch/fuzz/debugger-attach flags on rewritten heads stream
    forever or wait for a debugger — never_wrap (jest/vitest watch live in
    their own predicate above)."""
    head = argv[0]
    rest = argv[1:]
    if head == "tsc":
        # tsc strips 1-2 dashes, case-insensitive; -w is the short form.
        return any(t.lower().lstrip("-") in ("watch", "w") for t in rest)
    if head == "ruff":
        return "--watch" in rest
    if head == "go":
        for tok in rest:
            name = tok.lstrip("-").split("=", 1)[0]
            if name.startswith("test."):
                name = name[5:]
            if name == "fuzz":
                return True
        return False
    if head == "vitest":
        for tok in rest:
            name = tok.split("=", 1)[0]
            if name in ("--inspect", "--inspect-brk", "--api",
                        "--browser") or name.startswith("--browser."):
                return True
        return False
    if head == "pytest":
        return "--pdb" in rest
    return False


def _is_gh(argv):
    """TK-55: `gh pr checks <N> --watch` streams until checks finish, but the
    positional PR number sits between the verb and the flag, which the
    prefix-based FAMILIES stream_specs cannot express — the flag is matched
    anywhere after the ("pr", "checks") prefix instead."""
    verbs = cli_families.effective_verbs(argv)
    if not verbs or list(verbs[:2]) != ["pr", "checks"]:
        return False
    return "--watch" in verbs[2:]


def _is_redis_monitor(argv):
    return argv[0] == "redis-cli" and any(
        tok.upper() == "MONITOR" for tok in argv[1:]
    )


def _is_flutter(argv):
    if argv[0] != "flutter" or len(argv) < 2:
        return False
    sub = argv[1]
    if sub in _FLUTTER_STREAM_SUBS:
        return True
    if sub == "emulators":
        return "--launch" in argv[2:]
    if sub == "doctor":
        return "--android-licenses" in argv[2:]
    return False


def _is_login(argv):
    if argv[0] in _LOGIN_HEADS and len(argv) >= 2 and argv[1] == "login":
        return True
    return (
        argv[0] == "gcloud" and len(argv) >= 3
        and argv[1] == "auth" and argv[2] == "login"
    )


def _is_repl(argv):
    if argv[0] not in _REPL_HEADS:
        return False
    rest = argv[1:]
    if not rest:
        return True
    if "-c" in rest:
        return False
    positional = [tok for tok in rest if not tok.startswith("-")]
    if not positional:
        return False
    if argv[0] == "sqlite3" and len(positional) >= 2:
        # H-F3/N-F6 (TK-43): `sqlite3 <db> "<SQL>"` runs one batch and
        # exits - not a REPL (pinned change of the pre-TK-43 behavior;
        # bare `sqlite3 <db>` below stays a REPL).
        return False
    return True


def _is_swift(argv):
    """swift repl is a REPL; swift run launches the built executable - both
    interactive (TK-42). `swift build/test` stay on the generous builder
    class via _LONG_OPS."""
    if argv[0] != "swift" or len(argv) < 2:
        return False
    if argv[1] == "repl":
        return "-c" not in argv[2:]
    return argv[1] == "run"


def _is_xcodebuild_interactive(argv):
    """Bare xcodebuild (including no arguments at all - no -scheme/
    -destination) builds the default scheme and can stall on interactive
    signing prompts; -allowProvisioningUpdates talks to Apple's signing UI.
    Never-wrap both (TK-42)."""
    if argv[0] != "xcodebuild":
        return False
    rest = argv[1:]
    if "-allowProvisioningUpdates" in rest:
        return True
    return "-scheme" not in rest and "-destination" not in rest


_NEVER_WRAP_PREDICATES = (
    _is_tail,
    _is_kubectl,
    _is_docker,
    _is_wrangler_tail,
    _is_redis_monitor,
    _is_flutter,
    _is_login,
    _is_repl,
    _is_swift,
    _is_xcodebuild_interactive,
    _is_cloud_stream,
    _is_gh,
    _is_jest_vitest_watch,
    _is_watch_fuzz_debug,
)


def _is_docker_compose_long(argv):
    """H-F12: `up`/`build` after the `compose` token -> long builder.
    Covers the detached/flag-full forms (`docker compose -f x.yml up -d`,
    `docker --context prod compose build`) that the prefix-based _LONG_OPS
    entry ("docker", "compose", "up") cannot match; that entry still covers
    the flag-less `docker compose up -d`. Never-wrap (streaming compose up)
    is decided earlier in _classify, so this only widens the timeout."""
    if argv[0] != "docker" or len(argv) < 2:
        return False
    rest = argv[1:]
    if "compose" not in rest:
        return False
    after = rest[rest.index("compose") + 1:]
    return any(tok in ("up", "build") for tok in after)


def _is_generous(argv):
    for prefix in _LONG_OPS:
        if argv[: len(prefix)] == list(prefix):
            return True
    return _is_docker_compose_long(argv)


def _classify(argv):
    if not argv:
        return "default"
    if any(predicate(argv) for predicate in _NEVER_WRAP_PREDICATES):
        return "never_wrap"
    if _is_generous(argv):
        return "generous"
    return "default"


def classify(argv):
    """Return "never_wrap", "generous" or "default" for an exec-array."""
    try:
        return _classify(list(argv))
    except Exception:
        return "default"


def is_interactive_prompt(text):
    """True when output looks like it is waiting for an interactive answer."""
    if not text:
        return False
    try:
        lowered = text.lower()
        return any(pattern.lower() in lowered for pattern in _PROMPT_PATTERNS)
    except Exception:
        return False
