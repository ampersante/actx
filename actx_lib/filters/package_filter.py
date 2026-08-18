from actx_lib import runner


def _run_compact(args, config, parser):
    cmd = list(args)
    result = runner.execute(cmd)
    if result is None:
        return 1
    return runner.compacted_result(
        cmd, result, config, runner.stdout_compactor(parser), strategy="package"
    )


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


_NPM_NOISE_PREFIXES = (
    "npm warn ",
    "npm notice ",
    "added ",
    "removed ",
    "changed ",
    "audited ",
    "funding ",
    "run `npm ",
)


def compact_npm_install(text):
    kept = []
    summary = []
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if any(lower.startswith(prefix) for prefix in _NPM_NOISE_PREFIXES):
            continue
        if stripped.startswith("up to date") or "packages in" in lower:
            summary.append(stripped)
            continue
        if lower.startswith("error") or lower.startswith("err!"):
            kept.append(line)
            continue
        kept.append(line)
    parts = kept + summary
    return "\n".join(parts)


def compact_pip_install(text):
    out = []
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("Collecting ", "Downloading ", "Using cached ", "Requirement already")):
            continue
        if stripped.startswith("Installing collected packages:"):
            out.append(stripped)
            continue
        if stripped.startswith(("Successfully installed", "ERROR", "error:")):
            out.append(stripped)
            continue
        if set(stripped) <= {"-", " ", "="}:
            continue
        out.append(line)
    return "\n".join(out)


def run_pip(args, config):
    if args and args[0] == "install":
        return _run_compact(["pip"] + args, config, compact_pip_install)
    return _run_compact(["pip"] + args, config, compact_pip)


def run_uv(args, config):
    if args and args[0] == "run":
        return _run_compact(["uv"] + args, config, compact_uv_run)
    if args and args[0] == "pip" and len(args) >= 2 and args[1] == "install":
        return _run_compact(["uv"] + args, config, compact_uv_run)
    return runner.run_passthrough(["uv"] + args)


def run_npm(args, config):
    if not args:
        return runner.run_passthrough(["npm"] + args)
    if args[0] == "list":
        return _run_compact(["npm"] + args, config, compact_npm_list)
    if args[0] in ("install", "ci"):
        return _run_compact(["npm"] + args, config, compact_npm_install)
    return runner.run_passthrough(["npm"] + args)


def run_pnpm(args, config):
    if not args:
        return runner.run_passthrough(["pnpm"] + args)
    if args[0] == "list":
        return _run_compact(["pnpm"] + args, config, compact_pnpm_list)
    if args[0] in ("install", "ci"):
        return _run_compact(["pnpm"] + args, config, compact_npm_install)
    return runner.run_passthrough(["pnpm"] + args)
