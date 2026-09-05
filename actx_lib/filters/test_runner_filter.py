import re

from actx_lib import runner
from actx_lib.filters import compact_profiles

TOOLS = ("pytest", "cargo", "go", "jest", "vitest")


def _counter(failed, passed):
    return "%d failed, %d passed" % (failed, passed)


def parse_pytest(text):
    # Migrated onto the declarative profile engine (TK-50); byte-identical
    # output is enforced by the golden dumps in tests/fixtures/golden/.
    return compact_profiles.parse_test(text, compact_profiles.PROFILES["pytest"])


def parse_cargo_test(text):
    return compact_profiles.parse_test(
        text, compact_profiles.PROFILES["cargo_test"]
    )


# go/jest/vitest stay hand-written: their keep-block machines have per-tool
# quirks (standalone FAIL lines, pending-file emission) the profile
# vocabulary would distort; see TK-50 report. Goldens still pin them.
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

    return runner.compacted_result(cmd, result, config, compact_fn, strategy="test")


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
