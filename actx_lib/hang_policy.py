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

_LOGIN_HEADS = frozenset({
    "wrangler", "railway", "gcloud", "vercel", "netlify", "supabase",
    "flyctl", "fly",
})
_REPL_HEADS = frozenset({"psql", "sqlite3", "duckdb", "mongosh"})
_FLUTTER_STREAM_SUBS = frozenset({"run", "attach", "logs"})

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
    ("pytest",),
    ("cargo", "test"),
    ("go", "test"),
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
    global flags, then a stream_specs prefix must match exactly. Covers
    `railway logs -f`, `vercel logs --follow` and the env/variables/secret
    verbs of every family (Q2: never-wrap, exit 125). Logins and
    `wrangler tail` are kept in their dedicated predicates above - the table
    does not duplicate them."""
    spec = cli_families.FAMILIES.get(argv[0])
    if spec is None:
        return False
    rest = argv[1:]
    idx = 0
    while idx < len(rest) and rest[idx] in spec["global_flags"]:
        idx += 1
    rest = rest[idx:]
    return any(tuple(rest[: len(seq)]) == seq for seq in spec["stream_specs"])


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
    return any(not tok.startswith("-") for tok in rest)


def _is_swift_repl(argv):
    if argv[0] != "swift" or len(argv) < 2:
        return False
    return argv[1] == "repl" and "-c" not in argv[2:]


_NEVER_WRAP_PREDICATES = (
    _is_tail,
    _is_kubectl,
    _is_docker,
    _is_wrangler_tail,
    _is_redis_monitor,
    _is_flutter,
    _is_login,
    _is_repl,
    _is_swift_repl,
    _is_cloud_stream,
)


def _is_generous(argv):
    for prefix in _LONG_OPS:
        if argv[: len(prefix)] == list(prefix):
            return True
    return False


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
