import sys

from actx_lib import runner

_DIFF_PASSTHROUGH = {
    "--stat", "--numstat", "--name-only", "--name-status",
    "--check", "--quiet", "--output", "--exit-code",
}

_LOG_PASSTHROUGH = {
    "-p", "--stat", "--graph", "--numstat", "--name-only",
    "--name-status", "--format", "--pretty",
}

_BRANCH_READ_ONLY = {
    "-a", "-r", "-l", "--list", "--show-current",
    "-v", "--verbose", "-vv", "--no-color",
}


def _clip(text, limit):
    if len(text) <= limit:
        return text
    return text[:limit]


def _failure(cmd, result, config, tee_policy="auto"):
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if runner.tee_decision(config, tee_policy, result.returncode):
        runner.write_tee(cmd, result, config)
    return result.returncode


def _branch_name():
    result = runner.execute(["git", "symbolic-ref", "--short", "HEAD"])
    if result is None or result.returncode != 0:
        return None
    return result.stdout.strip()


def _group_status(porcelain):
    groups = []
    index = {}
    for line in porcelain.split("\n"):
        if not line:
            continue
        key = line[:2].strip()
        path = line[3:]
        if key not in index:
            index[key] = len(groups)
            groups.append((key, []))
        groups[index[key]][1].append(path)
    return groups


def _status(rest, config):
    if rest:
        return runner.run_passthrough(["git", "status"] + rest)
    cmd = ["git", "status", "--porcelain=v1"]
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        return _failure(cmd, result, config)

    try:
        branch = _branch_name()
        groups = _group_status(result.stdout)
        out = []
        if config.get("ultra_compact"):
            if branch is not None:
                out.append("* " + branch)
            elif not groups:
                out.append("no commits yet")
            for key, paths in groups:
                shown = paths[:200]
                out.append("%s:%d %s" % (key, len(paths), " ".join(shown)))
                if len(paths) > 200:
                    out.append("  ... (%d more)" % (len(paths) - 200))
        else:
            if branch is not None:
                out.append("* " + branch)
            elif not groups:
                out.append("no commits yet")
            for key, paths in groups:
                out.append("%s (%d):" % (key, len(paths)))
                out.extend("  " + path for path in paths[:200])
                if len(paths) > 200:
                    out.append("  ... (%d more)" % (len(paths) - 200))
        if out:
            print("\n".join(out))
        return 0
    except Exception:
        return runner.raw_fallback(result)


def _diff_path(header):
    marker = " b/"
    if marker not in header:
        return header[len("diff --git "):]
    left, right = header.split(marker, 1)
    if "a/" in left:
        old = left.split("a/", 1)[1]
    else:
        old = left[len("diff --git "):]
    if old != right:
        return "%s -> %s" % (old, right)
    return old


def _format_diff_block(block):
    header = block[0]
    additions = 0
    deletions = 0
    preview = []
    for line in block[1:]:
        if line.startswith("+") and not line.startswith("+++"):
            additions += 1
            preview.append(line)
        elif line.startswith("-") and not line.startswith("---"):
            deletions += 1
            preview.append(line)
    out = [_diff_path(header), "+%d -%d" % (additions, deletions)]
    out.extend(_clip(line, 300) for line in preview[:5])
    if len(preview) > 5:
        out.append("... (truncated, full in tee)")
    return out


def _split_diff_blocks(stdout):
    blocks = []
    current = None
    for line in stdout.split("\n"):
        if line.startswith("diff --git "):
            if current is not None:
                blocks.append(current)
            current = [line]
        elif current is not None:
            current.append(line)
    if current is not None:
        blocks.append(current)
    return blocks


def _diff(rest, config):
    if any(arg in _DIFF_PASSTHROUGH for arg in rest):
        return runner.run_passthrough(["git", "diff"] + rest)
    cmd = ["git", "diff"] + rest
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        return _failure(cmd, result, config, tee_policy="always")
    if len(result.stdout) <= 1000:
        runner.print_raw(result)
        return result.returncode

    try:
        out = []
        for block in _split_diff_blocks(result.stdout):
            out.extend(_format_diff_block(block))
        if out:
            print("\n".join(out))
        runner.write_tee(cmd, result, config)
        return 0
    except Exception:
        return runner.raw_fallback(result)


def _log(rest, config):
    if any(arg in _LOG_PASSTHROUGH for arg in rest):
        return runner.run_passthrough(["git", "log"] + rest)
    rest = [arg for arg in rest if arg != "--oneline"]
    cmd = ["git", "log", "--oneline"] + rest
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        return _failure(cmd, result, config)
    try:
        if result.stdout:
            print(result.stdout, end="")
            if not result.stdout.endswith("\n"):
                print()
        return 0
    except Exception:
        return runner.raw_fallback(result)


def _branch(rest, config):
    if not rest or all(arg in _BRANCH_READ_ONLY for arg in rest):
        return runner.run_passthrough(["git", "branch"] + rest)
    cmd = ["git", "branch"] + rest
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        return _failure(cmd, result, config)
    try:
        print("ok")
        return 0
    except Exception:
        return runner.raw_fallback(result)


def _mutating(sub, rest, config):
    cmd = ["git", sub] + rest
    result = runner.execute(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        return _failure(cmd, result, config)
    try:
        if sub == "commit":
            rev = runner.execute(["git", "rev-parse", "--short", "HEAD"])
            if rev is not None and rev.returncode == 0:
                print("ok %s" % rev.stdout.strip())
                return 0
        print("ok")
        return 0
    except Exception:
        return runner.raw_fallback(result)


def run(args, config):
    if not args:
        return runner.run_passthrough(["git"])
    sub = args[0]
    rest = args[1:]
    if sub == "status":
        return _status(rest, config)
    if sub == "diff":
        return _diff(rest, config)
    if sub == "log":
        return _log(rest, config)
    if sub == "branch":
        return _branch(rest, config)
    if sub in {"add", "commit", "push", "pull"}:
        return _mutating(sub, rest, config)
    return runner.run_passthrough(["git"] + args)
