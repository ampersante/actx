import re

from actx_lib import runner

TOOLS = ("pytest", "cargo", "go", "jest", "vitest")


def _int_re(text, pattern):
    match = re.search(pattern, text)
    return int(match.group(1)) if match else 0


def _strip_section(text, start, end=None):
    index = text.find(start)
    if index == -1:
        return ""
    index += len(start)
    if end is None:
        return text[index:]
    end_index = text.find(end, index)
    if end_index == -1:
        return text[index:]
    return text[index:end_index]


def _counter(failed, passed):
    return "%d failed, %d passed" % (failed, passed)


def parse_pytest(text):
    block = _strip_section(
        text, "=== FAILURES ===\n", "\n=== short test summary info ==="
    ).strip()
    groups = {}
    summary = _strip_section(text, "=== short test summary info ===")
    for line in summary.splitlines():
        match = re.match(r"FAILED\s+(\S+)\s+-\s+(.*)", line)
        if match:
            spec, reason = match.groups()
            file = spec.split("::", 1)[0]
            groups.setdefault(file, []).append("%s - %s" % (spec, reason))
    parts = []
    if block:
        parts.append(block)
    for file in sorted(groups):
        parts.append("%s:" % file)
        parts.extend("  " + item for item in groups[file])
    failed = _int_re(text, r"(\d+) failed") + _int_re(text, r"(\d+) error")
    passed = _int_re(text, r"(\d+) passed")
    return {"failures": "\n".join(parts), "failed": failed, "passed": passed}


def parse_cargo_test(text):
    failed = 0
    passed = 0
    for match in re.finditer(r"(\d+) passed; (\d+) failed", text):
        passed += int(match.group(1))
        failed += int(match.group(2))
    block = _strip_section(text, "failures:", "test result:")
    return {"failures": block.strip(), "failed": failed, "passed": passed}


def parse_go_test(text):
    out = []
    failed = 0
    passed = 0
    keep = False
    for line in text.split("\n"):
        if line.startswith("--- PASS:"):
            passed += 1
            keep = False
            continue
        if line.startswith("--- FAIL:"):
            failed += 1
            keep = True
            out.append(line)
            continue
        if keep and line.startswith(("    ", "\t")):
            out.append(line)
            continue
        if line.startswith("FAIL"):
            out.append(line)
            keep = False
            continue
        keep = False
    return {"failures": "\n".join(out).strip(), "failed": failed, "passed": passed}


def parse_jest(text):
    match = re.search(r"Tests:\s+(\d+) failed,\s+(\d+) passed", text)
    failed = int(match.group(1)) if match else 0
    passed = int(match.group(2)) if match else 0
    out = []
    keep = False
    for line in text.split("\n"):
        if line.startswith("PASS "):
            keep = False
            continue
        if line.startswith("FAIL "):
            keep = True
            out.append(line)
            continue
        if line.startswith(("Test Suites:", "Tests:", "Snapshots:", "Time:")):
            keep = False
            continue
        if keep:
            out.append(line)
    return {"failures": "\n".join(out).strip(), "failed": failed, "passed": passed}


def parse_vitest(text):
    match = re.search(r"Tests\s+(\d+) failed\s*\|\s*(\d+) passed", text)
    failed = int(match.group(1)) if match else 0
    passed = int(match.group(2)) if match else 0
    out = []
    current_file = None
    keep = False
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("✓"):
            current_file = None
            keep = False
            continue
        if stripped.startswith("❯"):
            current_file = stripped[1:].strip()
            keep = False
            continue
        if stripped.startswith("×"):
            if current_file is not None:
                out.append(current_file)
                current_file = None
            keep = True
            out.append(line)
            continue
        if keep and stripped.startswith("→"):
            out.append(line)
            continue
        if stripped.startswith("Test Files") or stripped.startswith("Tests"):
            keep = False
            continue
        keep = False
    return {"failures": "\n".join(out).strip(), "failed": failed, "passed": passed}


TOOL_PARSERS = {
    "pytest": parse_pytest,
    "cargo": parse_cargo_test,
    "go": parse_go_test,
    "jest": parse_jest,
    "vitest": parse_vitest,
}


def compact(text, tool):
    data = TOOL_PARSERS[tool](text)
    parts = []
    if data["failures"].strip():
        parts.append(data["failures"])
    parts.append(_counter(data["failed"], data["passed"]))
    return "\n".join(parts)


def detect(args):
    if not args:
        return None
    name = args[0].split("/")[-1]
    if name == "pytest":
        return "pytest"
    if name == "cargo" and len(args) >= 2 and args[1] == "test":
        return "cargo"
    if name == "go" and len(args) >= 2 and args[1] == "test":
        return "go"
    if name == "jest":
        return "jest"
    if name == "vitest":
        return "vitest"
    return None


def _run_tool(tool, cmd, config, failures_only=False):
    result = runner.execute(cmd)
    if result is None:
        return 1

    def compact_fn(result):
        if not result.stdout:
            return None
        data = TOOL_PARSERS[tool](result.stdout)
        if failures_only:
            return data["failures"]
        parts = []
        if data["failures"].strip():
            parts.append(data["failures"])
        parts.append(_counter(data["failed"], data["passed"]))
        return "\n".join(parts)

    return runner.compacted_result(cmd, result, config, compact_fn)


def run_pytest(args, config):
    return _run_tool("pytest", ["pytest"] + args, config)


def run_cargo_test(args, config):
    return _run_tool("cargo", ["cargo"] + args, config)


def run_go_test(args, config):
    return _run_tool("go", ["go"] + args, config)


def run_jest(args, config):
    return _run_tool("jest", ["jest"] + args, config)


def run_vitest(args, config):
    return _run_tool("vitest", ["vitest"] + args, config)


def run_failures(args, config):
    tool = detect(args)
    if tool is None:
        return runner.run_passthrough(args)
    return _run_tool(tool, args, config, failures_only=True)
