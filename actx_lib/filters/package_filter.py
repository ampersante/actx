from actx_lib import runner


def _run_compact(args, config, parser):
    cmd = list(args)
    result = runner.execute(cmd)
    if result is None:
        return 1
    return runner.compacted_result(cmd, result, config, runner.stdout_compactor(parser))


def _is_rule_line(line):
    stripped = line.strip()
    return stripped and set(stripped) <= {"-", " "}


def compact_pip(text):
    out = []
    for line in text.split("\n"):
        if not line.strip():
            continue
        if line.strip().startswith("Package"):
            continue
        if _is_rule_line(line):
            continue
        out.append(line)
    return "\n".join(out)


_UV_NOISE_PREFIXES = (
    "Resolved ",
    "Downloading ",
    "Prepared ",
    "Installed ",
    "Audited ",
    "Building ",
    "Updated ",
    "Uninstalled ",
)

_UV_SPINNER_CHARS = set("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")


def compact_uv_run(text):
    out = []
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith(_UV_NOISE_PREFIXES):
            continue
        if any(char in stripped for char in _UV_SPINNER_CHARS):
            continue
        out.append(line)
    while out and out[-1].strip() == "":
        out.pop()
    return "\n".join(out)


def compact_npm_list(text):
    out = []
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if line.startswith((" ", "├", "└", "│")):
            out.append(line)
    return "\n".join(out)


def compact_pnpm_list(text):
    out = []
    in_section = False
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("Legend:") or stripped.startswith("project@"):
            continue
        if stripped.endswith(":"):
            out.append(line)
            in_section = True
            continue
        if in_section:
            out.append(line)
    return "\n".join(out)


def run_pip(args, config):
    return _run_compact(["pip"] + args, config, compact_pip)


def run_uv(args, config):
    if not args or args[0] != "run":
        return runner.run_passthrough(["uv"] + args)
    return _run_compact(["uv"] + args, config, compact_uv_run)


def run_npm(args, config):
    if not args or args[0] != "list":
        return runner.run_passthrough(["npm"] + args)
    return _run_compact(["npm"] + args, config, compact_npm_list)


def run_pnpm(args, config):
    if not args or args[0] != "list":
        return runner.run_passthrough(["pnpm"] + args)
    return _run_compact(["pnpm"] + args, config, compact_pnpm_list)
