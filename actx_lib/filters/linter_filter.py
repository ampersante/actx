import re

from actx_lib import runner
from actx_lib.filters import compact_profiles


def _run_compact(args, config, parser):
    cmd = list(args)
    result = runner.execute(cmd)
    if result is None:
        return 1
    return runner.compacted_result(
        cmd, result, config, runner.stdout_compactor(parser), strategy="linter"
    )


def compact_ruff(text):
    # Migrated onto the declarative profile engine (TK-50); byte-identical
    # output is enforced by the golden dumps in tests/fixtures/golden/.
    return compact_profiles.parse_lint(text, compact_profiles.PROFILES["ruff"])


def compact_tsc(text):
    return compact_profiles.parse_lint(text, compact_profiles.PROFILES["tsc"])


# eslint/cargo/next stay hand-written: their keep rules are conditional on
# line shape and cross-line state (indent+warning policy, fallback error
# count, section-triggered state machine) that the profile vocabulary would
# distort; see TK-50 report. Goldens still pin their output byte-for-byte.
def compact_eslint(text):
    out = []
    errors = 0
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("✖"):
            continue
        if line.startswith((" ", "\t")):
            if "error" in stripped:
                out.append(line)
                errors += 1
            continue
        out.append(line)
    if errors:
        out.append("%d errors" % errors)
    return "\n".join(out)


def compact_golangci_lint(text):
    return compact_profiles.parse_lint(text, compact_profiles.PROFILES["golangci"])


def _cargo_error_count(text):
    match = re.search(r"due to (\d+) previous error", text)
    if match:
        return int(match.group(1))
    return len(re.findall(r"^error(?:\[|:)", text, re.M))


def compact_cargo(text):
    out = []
    in_error = False
    for line in text.split("\n"):
        if line.startswith(
            (
                "   Compiling",
                "    Finished",
                "   Building",
                "    Checking",
                "       Fresh",
                "       Dirty",
                "   Downloading",
                "     Locking",
            )
        ):
            continue
        if line.startswith("warning") or line.startswith("    = warning"):
            in_error = False
            continue
        if line.startswith("error"):
            in_error = True
            out.append(line)
            continue
        if in_error and (line.startswith(" ") or line.strip() == ""):
            out.append(line)
            continue
        in_error = False
    while out and out[-1].strip() == "":
        out.pop()
    out.append("%d errors" % _cargo_error_count(text))
    return "\n".join(out)


def compact_next(text):
    out = []
    in_failure = False
    for line in text.split("\n"):
        if line.startswith(
            (
                "   ▲",
                "   Creating",
                "   Linting",
                " ✓ Compiled",
                " ✓ ",
                "   Generating",
                "   Finalizing",
            )
        ):
            continue
        if line.strip() == "Failed to compile.":
            in_failure = True
            out.append(line)
            continue
        if in_failure:
            if line.startswith("> Build failed"):
                out.append(line)
                break
            out.append(line)
    return "\n".join(out).strip()


def run_ruff(args, config):
    return _run_compact(["ruff"] + args, config, compact_ruff)


def run_tsc(args, config):
    return _run_compact(["tsc"] + args, config, compact_tsc)


def run_eslint(args, config):
    return _run_compact(["eslint"] + args, config, compact_eslint)


def run_golangci_lint(args, config):
    return _run_compact(["golangci-lint"] + args, config, compact_golangci_lint)


def run_cargo(args, config):
    sub = args[0] if args else "build"
    if sub == "build":
        return _run_compact(["cargo"] + args, config, compact_cargo)
    if sub == "clippy":
        return _run_compact(["cargo"] + args, config, compact_cargo)
    return runner.run_passthrough(["cargo"] + args)


def run_next(args, config):
    return _run_compact(["next"] + args, config, compact_next)
