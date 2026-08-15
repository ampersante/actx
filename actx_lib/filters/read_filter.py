import os
import re
import sys

from actx_lib import runner

_C_COMMENT_EXTS = {".js", ".ts", ".c", ".h", ".cpp", ".java", ".rs", ".go"}
_AGGRESSIVE_EXTS = {".py", ".rs", ".go", ".js", ".ts", ".tsx", ".jsx"}


def _is_py_comment(index, line):
    stripped = line.lstrip()
    if index == 0:
        return stripped.startswith("#") and not stripped.startswith("#!")
    return stripped.startswith("#")


def _indent(line):
    return len(line) - len(line.lstrip())


def _py_signature(stripped):
    return stripped.startswith(("def ", "async def ", "class "))


def _strip_py_aggressive(text):
    """Textual approximation: keep signatures and top-level lines, drop
    function/class bodies, full-line comments and docstring blocks."""
    lines = text.split("\n")
    out = []
    stack = []
    in_docstring = False
    doc_delim = None
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        if in_docstring:
            if doc_delim in stripped:
                in_docstring = False
            continue
        if stripped == "":
            continue
        if index == 0 and stripped.startswith("#!"):
            out.append(line)
            continue
        if stripped.startswith("#"):
            continue
        if stripped.startswith('"""') or stripped.startswith("'''"):
            doc_delim = stripped[:3]
            in_docstring = doc_delim not in stripped[len(doc_delim):]
            continue
        indent = _indent(line)
        is_sig = _py_signature(stripped)
        while stack and indent <= stack[-1]:
            stack.pop()
        if is_sig:
            last = line.rfind(":")
            if last != -1:
                rest = line[last + 1:].strip()
                if rest and not rest.startswith("#"):
                    line = line[:last + 1]
            out.append(line)
            stack.append(indent)
        elif stripped.startswith("@"):
            out.append(line)
        elif stack:
            continue
        else:
            out.append(line)
    return "\n".join(out)


def _strip_js_ts_modifiers(stripped):
    return re.sub(
        r"^(?:export\s+default\s+|export\s+)?(?:async\s+)?", "", stripped
    )


def _strip_rust_modifiers(stripped):
    s = stripped
    while True:
        changed = False
        if s.startswith("pub"):
            rest = s[3:]
            if rest.startswith("("):
                end = rest.find(")")
                if end != -1:
                    s = rest[end + 1:].lstrip()
                    changed = True
                    continue
            elif rest.startswith((" ", "\t")):
                s = rest.lstrip()
                changed = True
                continue
        for qualifier in ("const ", "async ", "unsafe "):
            if s.startswith(qualifier):
                s = s[len(qualifier):].lstrip()
                changed = True
                break
        if not changed:
            break
    return s


def _strip_modifiers(stripped, ext):
    if ext in (".js", ".ts", ".tsx", ".jsx"):
        return _strip_js_ts_modifiers(stripped)
    if ext == ".rs":
        return _strip_rust_modifiers(stripped)
    return stripped


_C_LIKE_KEYWORDS = {
    ".rs": ("fn ", "struct ", "impl ", "trait ", "type ", "enum "),
    ".go": ("func ", "type "),
    ".js": ("function ", "class ", "const ", "let ", "var ", "interface ", "type "),
    ".ts": ("function ", "class ", "const ", "let ", "var ", "interface ", "type "),
    ".tsx": ("function ", "class ", "const ", "let ", "var ", "interface ", "type "),
    ".jsx": ("function ", "class ", "const ", "let ", "var ", "interface ", "type "),
}

_QUOTES = {
    ".rs": ('"',),
    ".go": ('"', "`"),
}


def _quotes(ext):
    return _QUOTES.get(ext, ('"', "'", "`"))


def _strip_block_comments(text):
    """Remove /* ... */ comments while preserving strings and inline code."""
    out = []
    in_block = False
    in_str = None
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_block:
            if char == "*" and index + 1 < len(text) and text[index + 1] == "/":
                in_block = False
                index += 2
                continue
        elif in_str:
            out.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == in_str:
                in_str = None
        elif char in ('"', "'", "`"):
            in_str = char
            out.append(char)
        elif char == "/" and index + 1 < len(text) and text[index + 1] == "*":
            in_block = True
            index += 2
            continue
        else:
            out.append(char)
        index += 1
    return "".join(out)


def _scan_braces(line, ext):
    """Return (first brace index, brace delta) ignoring strings and // comments."""
    quotes = _quotes(ext)
    in_str = None
    escaped = False
    first = -1
    delta = 0
    index = 0
    while index < len(line):
        char = line[index]
        if in_str:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == in_str:
                in_str = None
        else:
            if char in quotes:
                in_str = char
            elif char == "/" and index + 1 < len(line) and line[index + 1] == "/":
                break
            elif char == "{":
                if first == -1:
                    first = index
                delta += 1
            elif char == "}":
                delta -= 1
        index += 1
    return first, delta


def _strip_c_like_aggressive(text, ext):
    """Textual approximation: keep signature lines, drop braced bodies and
    full-line/block comments; inline comments are preserved."""
    cleaned = _strip_block_comments(text)
    lines = cleaned.split("\n")
    out = []
    brace_depth = 0
    for line in lines:
        stripped = line.lstrip()
        if stripped == "":
            continue
        if stripped.startswith("//"):
            continue
        is_sig = _strip_modifiers(stripped, ext).startswith(
            _C_LIKE_KEYWORDS.get(ext, ())
        )
        first, delta = _scan_braces(line, ext)
        if is_sig:
            if first != -1:
                line = line[:first + 1]
            out.append(line)
            brace_depth += delta
        elif brace_depth > 0:
            brace_depth += delta
            continue
        else:
            out.append(line)
            brace_depth += delta
    return "\n".join(out)


def run(args, config):
    if not args:
        print("error: read requires a file", file=sys.stderr)
        return 1
    file = args[0]
    level = "none"
    if len(args) >= 2:
        if args[1] != "--level" or len(args) < 3:
            print("error: read expects --level <level>", file=sys.stderr)
            return 1
        level = args[2]
    if level not in ("none", "minimal", "aggressive"):
        print("error: unknown level: %s" % level, file=sys.stderr)
        return 1

    if level == "none":
        return runner.run_passthrough(["cat", file])

    ext = os.path.splitext(file)[1].lower()
    if level == "aggressive":
        if ext not in _AGGRESSIVE_EXTS:
            return runner.run_passthrough(["cat", file])
    elif ext != ".py" and ext not in _C_COMMENT_EXTS:
        return runner.run_passthrough(["cat", file])

    cmd = ["cat", file]
    try:
        result = runner.execute(cmd)
    except UnicodeDecodeError:
        return runner.run_passthrough(cmd)
    if result is None:
        return 1
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        if runner.tee_decision(config, "auto", result.returncode):
            runner.write_tee(cmd, result, config)
        return result.returncode

    try:
        if level == "aggressive":
            if ext == ".py":
                out = _strip_py_aggressive(result.stdout)
            else:
                out = _strip_c_like_aggressive(result.stdout, ext)
        else:
            lines = result.stdout.split("\n")
            if ext == ".py":
                kept = [
                    line for i, line in enumerate(lines)
                    if not _is_py_comment(i, line)
                ]
            else:
                kept = [
                    line for line in lines
                    if not line.lstrip().startswith("//")
                ]
            out = "\n".join(kept)
        if out:
            print(out, end="")
        runner.record_compacted(cmd, result, out, "read", newline=False)
        return 0
    except Exception:
        return runner.raw_fallback(result)
