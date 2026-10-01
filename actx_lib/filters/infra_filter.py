"""docker/kubectl/helm/gh/aws summary verbs. Views and inspections
(docker inspect, kubectl get/describe, helm template/get metadata/show,
gh views and `pr diff`) are the content class and logs (docker logs,
docker compose logs, kubectl logs) the log class (TK-61): cli.main runs
them through runner.run_content / runner.run_lossless and they never
reach this module."""

from actx_lib import cli_families, runner
from actx_lib.redaction import redact_text

# Secret values are masked by actx_lib.redaction (value masking, TK-61):
# the key and the line stay, only the value span becomes ‹masked›.


def _rle(text):
    lines = text.split("\n")
    out = []
    index = 0
    while index < len(lines):
        line = lines[index]
        end = index + 1
        while end < len(lines) and lines[end] == line:
            end += 1
        count = end - index
        if count == 1:
            out.append(line)
        else:
            out.append("%s (x%d)" % (line, count))
        index = end
    return "\n".join(out)


def _dedup_compact(text):
    return _rle(redact_text(text))


def _run_compact(args, config, parser):
    cmd = list(args)
    result = runner.execute(cmd)
    if result is None:
        return 1
    return runner.compacted_result(
        cmd, result, config, runner.stdout_compactor(parser), strategy="infra"
    )


# Local effective-verb skip (TK-41, H-F4): global docker flags before the
# verb are skipped; the value-taking globals --context/-H/--host consume
# their value (`=` forms are single tokens and skip as plain flags).
# cli_families.effective_verbs arrives with TK-40 and will replace this;
# deliberately minimal, do not widen.
_DOCKER_VALUE_FLAGS = ("--context", "-H", "--host")
# compose-level flags that sit between `compose` and its subcommand.
_COMPOSE_VALUE_FLAGS = (
    "-f", "--file", "-p", "--project-name", "--profile", "--env-file",
)


def _first_verb(args, value_flags):
    """Tokens from the first non-flag verb onward; None when flags only."""
    idx = 0
    n = len(args)
    while idx < n:
        tok = args[idx]
        if tok in value_flags:
            idx += 2
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        return args[idx:]
    return None


def run_docker(args, config):
    if not args:
        return runner.run_passthrough(["docker"])
    # Dispatch on the EFFECTIVE verb, not args[0]: global flags and their
    # values may precede it (docker --context prod ps).
    verbs = _first_verb(args, _DOCKER_VALUE_FLAGS)
    if verbs is None:
        return runner.run_passthrough(["docker"] + args)
    sub = verbs[0]
    if sub in ("ps", "images"):
        return _run_compact(["docker"] + args, config, _dedup_compact)
    if sub == "stats" and "--no-stream" in verbs[1:]:
        # Bare `docker stats` streams: it never reaches the parser — the
        # passthrough below refuses it via hang_policy (exit 125).
        return _run_compact(["docker"] + args, config, _dedup_compact)
    if sub == "system" and verbs[1:2] == ["df"]:
        return _run_compact(["docker"] + args, config, _dedup_compact)
    if sub == "compose":
        tail = _first_verb(verbs[1:], _COMPOSE_VALUE_FLAGS)
        if tail is not None and tail[0] == "ps":
            return _run_compact(["docker"] + args, config, _dedup_compact)
    return runner.run_passthrough(["docker"] + args)


# TK-40: dispatch by EFFECTIVE verbs (cli_families.effective_verbs), not by
# args[0] - `kubectl -n prod top pods` must compact, not passthrough (H-F4).
_KUBECTL_COMPACT_SUBS = frozenset({"top", "events"})


def run_kubectl(args, config):
    if not args:
        return runner.run_passthrough(["kubectl"])
    verbs = cli_families.effective_verbs(["kubectl"] + args)
    sub = verbs[0] if verbs else None
    if sub in _KUBECTL_COMPACT_SUBS:
        return _run_compact(["kubectl"] + args, config, _dedup_compact)
    return runner.run_passthrough(["kubectl"] + args)


# TK-40: helm compaction subset (plan §4 E2). String dedup only; `helm get
# values` never reaches it (stream_specs -> never-wrap, exit 125).
_HELM_COMPACT_SUBS = (
    ("list",),
    ("status",),
    ("history",),
)


def run_helm(args, config):
    if not args:
        return runner.run_passthrough(["helm"])
    verbs = cli_families.effective_verbs(["helm"] + args)
    for sub in _HELM_COMPACT_SUBS:
        if tuple(verbs[: len(sub)]) == sub:
            return _run_compact(["helm"] + args, config, _dedup_compact)
    return runner.run_passthrough(["helm"] + args)


def run_gh(args, config):
    if not args:
        return runner.run_passthrough(["gh"])
    sub = args[0]
    if sub in ("pr", "issue", "run"):
        return _run_compact(["gh"] + args, config, _dedup_compact)
    return runner.run_passthrough(["gh"] + args)


def run_aws(args, config):
    # Generic runner path: JSON is printed as its masked raw text (TK-61).
    if not args:
        return runner.run_passthrough(["aws"])
    return runner.run(["aws"] + args, config)
