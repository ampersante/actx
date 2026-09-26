"""TK-59 STEP-R3(d): line coverage of the security_gate package over the
gate corpus (tests/fixtures/gate_corpus.json), via the stdlib `trace`
module. Reports every line of actx_lib/security_gate/*.py that never
executed while evaluating the whole corpus - line coverage only (not
branch coverage; a line covered once may still hide an uncovered branch on
the same line - documented limitation, plan.md section 12).

Usage:
    python3 tools/gate_trace_coverage.py
"""

import json
import os
import sys
import trace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

PKG_DIR = os.path.join(ROOT, "actx_lib", "security_gate")
FIXTURE_PATH = os.path.join(ROOT, "tests", "fixtures", "gate_corpus.json")
COVERDIR = os.path.join(
    "/private/tmp/claude-501/-Users-eli-Desktop-Personal-projects-actx"
    "/4cb6c381-5933-4396-b0e9-46133b04763d/scratchpad",
    "gate_trace_cover",
)


def _run_corpus():
    import actx_lib.security_gate as security_gate

    with open(FIXTURE_PATH, encoding="utf-8") as f:
        fixture = json.load(f)

    old_home = os.environ.get("HOME")
    os.environ["HOME"] = fixture["home"]
    try:
        for command in fixture["corpus"]:
            security_gate.evaluate_security(command)
    finally:
        if old_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = old_home


def main():
    tracer = trace.Trace(count=True, trace=False, countfuncs=False, countcallers=False)
    tracer.runfunc(_run_corpus)
    results = tracer.results()

    os.makedirs(COVERDIR, exist_ok=True)
    results.write_results(show_missing=True, summary=False, coverdir=COVERDIR)

    pkg_files = sorted(
        f for f in os.listdir(PKG_DIR) if f.endswith(".py")
    )

    total_uncovered = 0
    for fname in pkg_files:
        # trace.CoverageResults names .cover files by dotted module name,
        # not by bare filename (e.g. actx_lib.security_gate.common.cover).
        modname = "actx_lib.security_gate." + fname[:-3]
        cover_name = modname + ".cover"
        cover_path = os.path.join(COVERDIR, cover_name)
        if not os.path.exists(cover_path):
            print(f"{fname}: NO COVER FILE WRITTEN (module never imported?)")
            continue
        with open(cover_path, encoding="utf-8") as f:
            lines = f.readlines()
        uncovered = [
            (i + 1, line.rstrip("\n"))
            for i, line in enumerate(lines)
            if line.startswith(">>>>>>")
        ]
        total_uncovered += len(uncovered)
        print(f"{fname}: {len(uncovered)} uncovered line(s) out of {len(lines)}")
        for lineno, line in uncovered:
            print(f"    {lineno}: {line}")

    print(f"\nTotal uncovered lines across the package: {total_uncovered}")
    print(f"Annotated .cover files written to: {COVERDIR}")


if __name__ == "__main__":
    main()
