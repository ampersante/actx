import json
import os
import re
import sys

_PATH = "~/.config/actx/filters.json"

KNOWN_KEYS = {
    "match_command",
    "strip_lines_matching",
    "keep_lines_matching",
    "replace",
    "max_lines",
    "tail_lines",
    "strip_ansi",
    "dedupe_lines",
}


def _strip_ansi(text):
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)


def _apply_rule(text, rule):
    lines = text.split("\n")
    if "strip_lines_matching" in rule:
        pattern = re.compile(rule["strip_lines_matching"])
        lines = [line for line in lines if not pattern.search(line)]
    if "keep_lines_matching" in rule:
        pattern = re.compile(rule["keep_lines_matching"])
        lines = [line for line in lines if pattern.search(line)]
    if "replace" in rule:
        replacement = rule["replace"]
        if not isinstance(replacement, dict) or "pattern" not in replacement:
            raise ValueError("replace must be an object with a pattern")
        pattern = re.compile(replacement["pattern"])
        lines = [
            pattern.sub(replacement.get("replacement", ""), line)
            for line in lines
        ]
    if "max_lines" in rule:
        lines = lines[: int(rule["max_lines"])]
    if "tail_lines" in rule:
        lines = lines[-int(rule["tail_lines"]):]
    if rule.get("strip_ansi"):
        lines = [_strip_ansi(line) for line in lines]
    if rule.get("dedupe_lines"):
        seen = set()
        deduped = []
        for line in lines:
            if line not in seen:
                seen.add(line)
                deduped.append(line)
        lines = deduped
    return "\n".join(lines)


def load():
    """Return rules, [] when absent/invalid, or None after printing an error
    for an unknown key. The file is never written by actx."""
    path = os.path.expanduser(_PATH)
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    rules = []
    for item in data:
        if not isinstance(item, dict):
            continue
        unknown = set(item) - KNOWN_KEYS
        if unknown:
            print(
                "error: unknown filters.json key(s): %s"
                % ", ".join(sorted(unknown)),
                file=sys.stderr,
            )
            return None
        rules.append(item)
    return rules


def apply(rules, command_name, text):
    """Apply matching rules in order; raises on invalid rule values so the
    caller can fall back to raw passthrough."""
    for rule in rules:
        match = rule.get("match_command")
        if match is not None and match != command_name:
            continue
        text = _apply_rule(text, rule)
    return text
