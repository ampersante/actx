import shlex

from actx_lib import cli_families

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
_CARGO_PURE_RO = frozenset({"check", "test", "build", "tree"})
_CARGO_1ARG_FLAGS = frozenset({
    "-q", "--quiet", "-v", "-vv", "-vvv", "--verbose",
    "--offline", "--locked", "--frozen",
})
_CARGO_2ARG_FLAGS = frozenset({
    "--color", "--config", "-C", "-Z", "--manifest-path", "--target-dir",
})

_WRITE_TOKENS = frozenset({"--fix", "fix", "format"})


def _parse_cargo(tokens):
    """Extracts (subcmd, cargo_args, forwarded_args) from cargo tokens."""
    idx = 1
    n = len(tokens)
    while idx < n:
        tok = tokens[idx]
        if tok == "--":
            return None, [], []
        if tok.startswith("+"):
            idx += 1
            continue
        if tok in _CARGO_1ARG_FLAGS:
            idx += 1
            continue
        if tok in _CARGO_2ARG_FLAGS:
            idx += 2
            continue
        if tok.startswith("--color=") or tok.startswith("--config=") or tok.startswith("-C=") or tok.startswith("-Z="):
            idx += 1
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        subcmd = tok
        rest = tokens[idx + 1 :]
        if "--" in rest:
            dash_idx = rest.index("--")
            cargo_args = rest[:dash_idx]
            forwarded_args = rest[dash_idx + 1 :]
        else:
            cargo_args = rest
            forwarded_args = []
        return subcmd, cargo_args, forwarded_args
    return None, [], []


def _cargo_ok(tokens):
    if len(tokens) < 2:
        return False
    subcmd, cargo_args, forwarded_args = _parse_cargo(tokens)
    if subcmd is None:
        return False

    if subcmd in _CARGO_PURE_RO:
        return True

    if subcmd == "clippy":
        return not any(tok == "--fix" or tok.startswith("--fix=") for tok in cargo_args)

    if subcmd == "fmt":
        all_args = cargo_args + forwarded_args
        has_check = "--check" in all_args
        has_emit_files = False
        for i, tok in enumerate(all_args):
            if tok in ("--emit=files", "--emit=file"):
                has_emit_files = True
                break
            if tok == "--emit" and i + 1 < len(all_args) and all_args[i + 1] in ("files", "file"):
                has_emit_files = True
                break
        return has_check and not has_emit_files

    if subcmd == "metadata":
        return "--no-deps" in cargo_args

    if subcmd == "package":
        return "--list" in cargo_args

    return False



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
    "cargo": _cargo_ok,
    "go": lambda t: len(t) >= 2 and t[1] == "test",
    "pip": _pip_ok,
    "uv": _uv_ok,
    "npm": _npm_ok,
    "pnpm": _npm_ok,
    "docker": _docker_ok,
    "kubectl": lambda t: len(t) >= 2 and t[1] in _KUBECTL_RO,
}


def _cloud_family_ok(tokens, global_flags, ro_verbs):
    """Family predicate: skip boolean global flags (exact tokens), then the
    remaining tokens must start with one of the ro_verbs sequences (exact
    token equality on every element). Stream/secret verbs are simply absent
    from ro_verbs, so they never match here."""
    rest = tokens[1:]
    idx = 0
    while idx < len(rest) and rest[idx] in global_flags:
        idx += 1
    rest = rest[idx:]
    for verb in ro_verbs:
        if tuple(rest[: len(verb)]) == verb:
            return True
    return False


# Cloud families join the dispatch from the declarative table (TK-39);
# manual predicates above are never overwritten.
for _head, _spec in cli_families.FAMILIES.items():
    if _head not in _DISPATCH:
        _DISPATCH[_head] = (
            lambda t, _spec=_spec: _cloud_family_ok(
                t, _spec["global_flags"], _spec["ro_verbs"]
            )
        )


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
