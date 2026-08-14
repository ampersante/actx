import json

from actx_lib import runner

_SECRET_PATTERNS = (
    "secret",
    "token",
    "password",
    "accesskey",
    "credential",
    "aws_access_key_id",
    "aws_secret_access_key",
)


def _is_secret_key(key):
    lowered = key.lower()
    return any(pattern in lowered for pattern in _SECRET_PATTERNS)


def _drop_secret_lines(text):
    return "\n".join(
        line for line in text.split("\n") if not any(p in line.lower() for p in _SECRET_PATTERNS)
    )


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
    return _rle(_drop_secret_lines(text))


def _drop_secret_json(obj):
    if isinstance(obj, dict):
        return {
            key: _drop_secret_json(value)
            for key, value in obj.items()
            if not _is_secret_key(key)
        }
    if isinstance(obj, list):
        return [_drop_secret_json(value) for value in obj]
    return obj


def compact_aws(text):
    stripped = text.strip()
    try:
        obj = json.loads(stripped)
    except ValueError:
        return _dedup_compact(text)
    return json.dumps(_drop_secret_json(obj), indent=2, sort_keys=True)


def _run_compact(args, config, parser):
    cmd = list(args)
    result = runner.execute(cmd)
    if result is None:
        return 1
    return runner.compacted_result(cmd, result, config, runner.stdout_compactor(parser))


def run_docker(args, config):
    if not args:
        return runner.run_passthrough(["docker"])
    sub = args[0]
    if sub in ("ps", "images", "logs"):
        return _run_compact(["docker"] + args, config, _dedup_compact)
    if sub == "compose" and len(args) >= 2 and args[1] == "ps":
        return _run_compact(["docker"] + args, config, _dedup_compact)
    return runner.run_passthrough(["docker"] + args)


def run_kubectl(args, config):
    if not args:
        return runner.run_passthrough(["kubectl"])
    sub = args[0]
    if sub == "logs":
        return _run_compact(["kubectl"] + args, config, _dedup_compact)
    if sub == "get":
        return _run_compact(["kubectl"] + args, config, _dedup_compact)
    return runner.run_passthrough(["kubectl"] + args)


def run_gh(args, config):
    if not args:
        return runner.run_passthrough(["gh"])
    sub = args[0]
    if sub in ("pr", "issue", "run"):
        return _run_compact(["gh"] + args, config, _dedup_compact)
    return runner.run_passthrough(["gh"] + args)


def run_aws(args, config):
    if not args:
        return runner.run_passthrough(["aws"])
    return _run_compact(["aws"] + args, config, compact_aws)
