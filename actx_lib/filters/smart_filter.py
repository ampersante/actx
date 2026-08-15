import os
import re
import sys

from actx_lib import runner

_EXTS = {".py", ".rs", ".ts"}


def _dedupe(items, limit=5):
    seen = []
    for item in items:
        if item not in seen:
            seen.append(item)
        if len(seen) == limit:
            break
    return seen


def _count_py(text):
    functions = 0
    classes = 0
    imports = []
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("def ") or stripped.startswith("async def "):
            functions += 1
        elif stripped.startswith("class "):
            classes += 1
        elif stripped.startswith("import "):
            imports.append(stripped[len("import "):].split()[0].split(".")[0])
        elif stripped.startswith("from "):
            imports.append(stripped[len("from "):].split()[0])
    return functions, classes, imports


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
        if s.startswith('extern "'):
            end = s.find('"', len('extern "'))
            if end != -1:
                s = s[end + 1:].lstrip()
                changed = True
                continue
        for qualifier in ("const ", "async ", "unsafe ", "safe "):
            if s.startswith(qualifier):
                s = s[len(qualifier):].lstrip()
                changed = True
                break
        if not changed:
            break
    return s


def _count_rust(text):
    functions = 0
    structs = 0
    impls = 0
    traits = 0
    imports = []
    for line in text.split("\n"):
        stripped = _strip_rust_modifiers(line.lstrip())
        if stripped.startswith("fn "):
            functions += 1
        elif stripped.startswith("struct "):
            structs += 1
        elif stripped.startswith("impl "):
            impls += 1
        elif stripped.startswith("trait "):
            traits += 1
        elif stripped.startswith("use "):
            imports.append(stripped[len("use "):].rstrip(";").strip())
    return functions, structs, impls, traits, imports


def _count_ts(text):
    functions = 0
    classes = 0
    interfaces = 0
    types = 0
    imports = []
    for line in text.split("\n"):
        stripped = re.sub(
            r"^(?:export\s+default\s+|export\s+)?(?:async\s+)?", "", line.lstrip()
        )
        if stripped.startswith("function "):
            functions += 1
        elif stripped.startswith("class "):
            classes += 1
        elif stripped.startswith("interface "):
            interfaces += 1
        elif stripped.startswith("type "):
            types += 1
        elif stripped.startswith("import "):
            match = re.search(r"from\s+[\"']([^\"']+)[\"']", stripped)
            if match:
                imports.append(match.group(1))
    return functions, classes, interfaces, types, imports


def _summarize(text, ext):
    if ext == ".py":
        functions, classes, imports = _count_py(text)
        lines = [
            "language: python",
            "functions: %d, classes: %d" % (functions, classes),
        ]
    elif ext == ".rs":
        functions, structs, impls, traits, imports = _count_rust(text)
        lines = [
            "language: rust",
            "functions: %d, structs: %d, impls: %d, traits: %d"
            % (functions, structs, impls, traits),
        ]
    else:
        functions, classes, interfaces, types, imports = _count_ts(text)
        lines = [
            "language: typescript",
            "functions: %d, classes: %d, interfaces: %d, types: %d"
            % (functions, classes, interfaces, types),
        ]
    if imports:
        lines.append("imports: " + ", ".join(_dedupe(imports)))
    return "\n".join(lines)


def run(args, config):
    if not args:
        print("error: smart requires a file", file=sys.stderr)
        return 1
    if len(args) > 1:
        print("error: smart takes exactly one file", file=sys.stderr)
        return 1
    file = args[0]
    ext = os.path.splitext(file)[1].lower()
    if ext not in _EXTS:
        print("unknown language")
        return 0

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
        out = _summarize(result.stdout, ext)
        print(out)
        runner.record_compacted(cmd, result, out, "smart")
        return 0
    except Exception:
        return runner.raw_fallback(result)
