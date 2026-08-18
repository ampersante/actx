import shlex

_FORBIDDEN = set("\n\r\t\0;&&|<>$`(){}#")

# Owned here so rewriter never imports filters (hook/rewrite perf boundary).
BRANCH_READ_ONLY = frozenset({
    "-a", "-r", "-l", "--list", "--show-current",
    "-v", "--verbose", "-vv", "--no-color",
})

_LS_FLAGS = frozenset({
    "-l", "-a", "-la", "-al", "-lh", "-lah", "-ahl", "-hal", "-hla", "-alh",
    "-1", "-F",
})

_GIT_RO = frozenset({"status", "diff", "log", "show", "blame", "rev-parse"})
_GIT_MUTATE = frozenset({"add", "commit", "push", "pull", "fetch"})

_PIP_RO = frozenset({"list", "show", "freeze", "outdated"})
_NPM_RO = frozenset({"list"})
_NPM_MUTATE = frozenset({"install", "ci"})
_DOCKER_RO = frozenset({"ps", "images", "logs"})
_KUBECTL_RO = frozenset({"get", "logs"})
_GH_RO = frozenset({"pr", "issue", "run"})
_CARGO_OK = frozenset({"test", "build", "clippy"})

_WRITE_TOKENS = frozenset({"--fix", "fix", "format"})


def _has_write_token(tokens):
    return any(tok in _WRITE_TOKENS or tok.startswith("--fix") for tok in tokens[1:])


def _git_ok(tokens):
    if len(tokens) < 2:
        return False
    if any(tok.startswith("--out") for tok in tokens):
        return False
    sub = tokens[1]
    if sub in _GIT_RO:
        return True
    if sub in _GIT_MUTATE:
        return True
    if sub == "branch":
        rest = tokens[2:]
        return (not rest) or all(arg in BRANCH_READ_ONLY for arg in rest)
    if sub == "stash" and len(tokens) >= 3 and tokens[2] == "list":
        return True
    return False


def _ls_ok(tokens):
    rest = tokens[1:]
    if not rest:
        return True
    flags = []
    paths = []
    for tok in rest:
        if tok.startswith("-"):
            flags.append(tok)
        else:
            paths.append(tok)
    if len(paths) > 1:
        return False
    if any(not p for p in paths):
        return False
    if flags and any(f not in _LS_FLAGS for f in flags):
        return False
    return True


def _find_ok(tokens):
    forbidden = {
        "-delete", "-exec", "-execdir", "-ok", "-okdir",
        "-fprint", "-fprintf", "-fls",
    }
    return forbidden.isdisjoint(tokens)


def _wc_family_ok(tokens):
    head = tokens[0]
    if head == "tail" and any(
        tok == "-f" or tok == "--follow" or tok.startswith("--follow=")
        for tok in tokens
    ):
        return False
    if head == "sort" and any(
        tok.startswith("-o") or tok == "--output" or tok.startswith("--output=")
        for tok in tokens
    ):
        return False
    return True


def _docker_ok(tokens):
    if len(tokens) < 2:
        return False
    if tokens[1] in _DOCKER_RO:
        return True
    if tokens[1] == "compose" and len(tokens) >= 3 and tokens[2] == "ps":
        return True
    return False


def _pip_ok(tokens):
    if len(tokens) < 2:
        return False
    sub = tokens[1]
    if sub in _PIP_RO:
        return True
    if sub == "install":
        return True
    return False


def _uv_ok(tokens):
    if len(tokens) < 2:
        return False
    if tokens[1] == "run":
        return True
    if tokens[1] == "pip" and len(tokens) >= 3 and tokens[2] == "install":
        return True
    return False


def _npm_ok(tokens):
    if len(tokens) < 2:
        return False
    return tokens[1] in _NPM_RO or tokens[1] in _NPM_MUTATE


def _ruff_ok(tokens):
    return not _has_write_token(tokens)


def _eslint_ok(tokens):
    return not _has_write_token(tokens)


def _next_ok(tokens):
    return not any(tok == "--fix" or tok.startswith("--fix") for tok in tokens[1:])


# head -> predicate(tokens) ; None predicate means always rewrite when head matches
_DISPATCH = {
    "git": _git_ok,
    "ls": _ls_ok,
    "grep": lambda _t: True,
    "find": _find_ok,
    "wc": _wc_family_ok,
    "head": _wc_family_ok,
    "tail": _wc_family_ok,
    "sort": _wc_family_ok,
    "uniq": _wc_family_ok,
    "rg": lambda _t: True,
    "cat": lambda _t: True,
    "tree": lambda _t: True,
    "gh": lambda t: len(t) >= 2 and t[1] in _GH_RO,
    "pytest": lambda _t: True,
    "jest": lambda _t: True,
    "vitest": lambda _t: True,
    "ruff": _ruff_ok,
    "eslint": _eslint_ok,
    "golangci-lint": lambda t: not _has_write_token(t),
    "tsc": lambda _t: True,
    "next": _next_ok,
    "cargo": lambda t: len(t) >= 2 and t[1] in _CARGO_OK,
    "go": lambda t: len(t) >= 2 and t[1] == "test",
    "pip": _pip_ok,
    "uv": _uv_ok,
    "npm": _npm_ok,
    "pnpm": _npm_ok,
    "docker": _docker_ok,
    "kubectl": lambda t: len(t) >= 2 and t[1] in _KUBECTL_RO,
}


def rewrite(command):
    if not command:
        return None
    if command.startswith("actx "):
        return None
    if len(command) > 4096:
        return None
    if any(ch in _FORBIDDEN for ch in command):
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if not tokens:
        return None

    pred = _DISPATCH.get(tokens[0])
    if pred is None:
        return None
    if not pred(tokens):
        return None
    return "actx " + command
