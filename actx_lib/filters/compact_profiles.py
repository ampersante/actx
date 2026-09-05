"""Declarative compaction profiles: data-driven output compactors.

A profile is plain data (regex strings, format strings, tuples). This module
is the single executor: new output families connect by adding a profile dict
to PROFILES, not by copying a parser (TK-50; groundwork for TK-42/TK-43).

Profile kinds:

- "linter": keep only lines matching ``keep_line``; when anything is kept,
  append ``suffix % count``. Covers ruff/tsc/golangci-style diagnostics.

- "test_runner": return a {"failures", "failed", "passed"} dict composed of:

  * ``section``: (start_literal, end_literal) — literal slice between the
    markers (pytest FAILURES block, cargo "failures:" dump);
  * ``failure_start`` + ``failure_continue``: line block machine — a line
    matching failure_start opens a kept block; following lines survive only
    while they match failure_continue; any other line closes it (progress
    noise is what fails the continuation, so it is dropped implicitly);
  * ``summary_after`` + ``summary_line`` + ``summary_format`` +
    ``group_by``: regex over the summary lines, items formatted with
    summary_format and grouped (``"file"`` = first group split on "::",
    emitted as "file:" plus two-space-indented items in sorted order; no
    grouping = flat item list);
  * ``counters``: {"failed": specs, "passed": specs} where each spec is
    (pattern, group, mode) and mode is "first" (first re.search match) or
    "sum" (sum over re.finditer); counter value = sum of spec values.

Engine contract: exceptions propagate (invalid profile data, unexpected
input) — the calling filter's compacted_result path fails open to raw
stdout+stderr with the original exit code (PRD.md 8, RK-03). This module is
imported only inside filter modules, never by the hook/rewrite paths (RK-02).
"""

import re


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


def _counter(text, specs):
    total = 0
    for pattern, group, mode in specs:
        compiled = re.compile(pattern)
        if mode == "first":
            match = compiled.search(text)
            if match:
                total += int(match.group(group))
        elif mode == "sum":
            for match in compiled.finditer(text):
                total += int(match.group(group))
        else:
            raise ValueError("unknown counter mode: %r" % (mode,))
    return total


def _failure_blocks(text, profile):
    starts = tuple(re.compile(p) for p in profile["failure_start"])
    continues = tuple(re.compile(p) for p in profile["failure_continue"])
    out = []
    keep = False
    for line in text.split("\n"):
        if any(p.search(line) for p in starts):
            keep = True
            out.append(line)
        elif keep and any(p.search(line) for p in continues):
            out.append(line)
        else:
            keep = False
    return "\n".join(out)


def _summary_groups(text, profile):
    region = text
    marker = profile.get("summary_after")
    if marker:
        region = _strip_section(text, marker)
    line_re = re.compile(profile["summary_line"])
    items = []
    groups = {}
    for line in region.splitlines():
        match = line_re.match(line)
        if not match:
            continue
        item = profile["summary_format"] % match.groups()
        items.append(item)
        if profile.get("group_by") == "file":
            groups.setdefault(match.group(1).split("::", 1)[0], []).append(item)
    parts = []
    if profile.get("group_by") == "file":
        for key in sorted(groups):
            parts.append("%s:" % key)
            parts.extend("  " + item for item in groups[key])
    else:
        parts.extend(items)
    return parts


def parse_test(text, profile):
    """Run a "test_runner" profile; returns {"failures", "failed", "passed"}."""
    parts = []
    section = profile.get("section")
    if section:
        end = section[1] if len(section) > 1 else None
        block = _strip_section(text, section[0], end).strip()
        if block:
            parts.append(block)
    if profile.get("failure_start"):
        block = _failure_blocks(text, profile).strip()
        if block:
            parts.append(block)
    parts.extend(_summary_groups(text, profile) if profile.get("summary_line") else [])
    counters = profile["counters"]
    return {
        "failures": "\n".join(parts),
        "failed": _counter(text, counters.get("failed", ())),
        "passed": _counter(text, counters.get("passed", ())),
    }


def parse_lint(text, profile):
    """Run a "linter" profile; returns the compacted text."""
    keep_re = re.compile(profile["keep_line"])
    out = [line for line in text.split("\n") if keep_re.search(line)]
    if out:
        out.append(profile["suffix"] % len(out))
    return "\n".join(out)


# name -> profile (data only; add new tools here, no engine changes)
PROFILES = {
    # --- test-runner class ---
    "pytest": {
        "kind": "test_runner",
        "section": ("=== FAILURES ===\n", "\n=== short test summary info ==="),
        "summary_after": "=== short test summary info ===",
        "summary_line": r"FAILED\s+(\S+)\s+-\s+(.*)",
        "summary_format": "%s - %s",
        "group_by": "file",
        "counters": {
            "failed": (
                (r"(\d+) failed", 1, "first"),
                (r"(\d+) error", 1, "first"),
            ),
            "passed": ((r"(\d+) passed", 1, "first"),),
        },
    },
    "cargo_test": {
        "kind": "test_runner",
        "section": ("failures:", "test result:"),
        "counters": {
            "failed": ((r"(\d+) passed; (\d+) failed", 2, "sum"),),
            "passed": ((r"(\d+) passed; (\d+) failed", 1, "sum"),),
        },
    },
    # Demo of a data-only connection (TK-43 groundwork): no engine code was
    # written for dbt — this dict plus a fixture is the whole integration.
    "dbt_run": {
        "kind": "test_runner",
        "failure_start": (r" ERROR ",),
        "failure_continue": (r"^\s+\S",),
        "counters": {
            "failed": ((r"ERROR=(\d+)", 1, "first"),),
            "passed": ((r"PASS=(\d+)", 1, "first"),),
        },
    },
    # --- linter class ---
    "ruff": {
        "kind": "linter",
        "keep_line": r"^\S+:\d+:\d+:",
        "suffix": "%d errors",
    },
    "tsc": {
        "kind": "linter",
        "keep_line": r"\(\d+,\d+\):\s*error TS\d+",
        "suffix": "%d errors",
    },
    "golangci": {
        "kind": "linter",
        "keep_line": r"^\S+\.go:\d+:\d+:",
        "suffix": "%d errors",
    },
}
