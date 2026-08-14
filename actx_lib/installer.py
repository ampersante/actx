"""Adapter installer for ``actx init`` / ``--show`` / ``--uninstall``.

All adapter paths resolve through :func:`os.path.expanduser` so tests can
override ``HOME``.  The installer only merges actx entries into existing user
files; it never rewrites those files wholesale.
"""

import json
import os
import shlex
import sys

AGENTS = ("claude", "codex", "opencode", "grok", "cursor", "cline", "windsurf", "aider")

INSTRUCTION_SECTION = """## Output compression (actx)

To reduce context noise, prefix read-only commands with `actx`:
- `git status` → `actx git status`
- `git diff` → `actx git diff`
- `git log` → `actx git log`
- `ls` → `actx ls`
- `grep` → `actx grep`
- `find` → `actx find`

Mutating commands run normally. For full output, run the command without `actx` or use `actx --raw <command>`.
"""

_SECTION_HEADER = "## Output compression (actx)"

# Per-agent integration points.  cursor has no file target: install prints the
# section to stdout for manual insertion in the Cursor UI.
_AGENT_PATHS = {
    "claude": {"hook": "~/.claude/settings.json"},
    "codex": {"hook": "~/.codex/hooks.json"},
    "opencode": {"plugin": "~/.config/opencode/plugins/actx.ts"},
    "grok": {"instructions": "~/.grok/AGENTS.md"},
    "cursor": {},
    "cline": {"instructions": "~/.cline/rules/actx.md"},
    "windsurf": {"instructions": "~/.codeium/windsurf/memories/global_rules.md"},
    "aider": {
        "instructions": "~/.config/actx/instructions.md",
        "conf": "~/.aider.conf.yml",
    },
}

_AIDER_READ_PATH = "~/.config/actx/instructions.md"


def abs_path():
    """Resolve the running ``actx`` binary to an absolute path."""
    return os.path.realpath(sys.argv[0])


def _hook_handler(abs_actx):
    return {
        "type": "command",
        "command": shlex.quote(abs_actx) + " hook",
        "timeout": 10,
    }


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("cannot parse JSON at %s" % path) from exc


def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


def _install_hook(path, abs_actx):
    """Merge the actx PreToolUse handler into a JSON settings file."""
    if os.path.exists(path):
        try:
            data = _read_json(path)
        except ValueError:
            raise
        if not isinstance(data, dict):
            raise ValueError("cannot install: %s is not a JSON object" % path)
    else:
        data = {}

    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    pretool = hooks.get("PreToolUse")
    if not isinstance(pretool, list):
        pretool = []
    else:
        pretool = list(pretool)

    handler = _hook_handler(abs_actx)
    handler_command = handler["command"]

    changed = False
    bash_entry = None
    for entry in pretool:
        if isinstance(entry, dict) and entry.get("matcher") == "Bash":
            bash_entry = entry
            break

    if bash_entry is None:
        bash_entry = {"matcher": "Bash", "hooks": []}
        pretool.append(bash_entry)
        changed = True

    entry_hooks = bash_entry.get("hooks")
    if not isinstance(entry_hooks, list):
        entry_hooks = []
        bash_entry["hooks"] = entry_hooks
        changed = True

    if not any(
        isinstance(existing, dict) and existing.get("command") == handler_command
        for existing in entry_hooks
    ):
        entry_hooks.append(handler)
        changed = True

    if changed:
        hooks["PreToolUse"] = pretool
        data["hooks"] = hooks
        _write_json(path, data)
    return changed


def _uninstall_hook(path, abs_actx):
    """Remove only the actx handler, pruning empty hook groups."""
    if not os.path.exists(path):
        return False
    data = _read_json(path)
    if not isinstance(data, dict):
        return False

    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return False
    pretool = hooks.get("PreToolUse")
    if not isinstance(pretool, list):
        return False

    handler_command = _hook_handler(abs_actx)["command"]
    changed = False
    kept_entries = []
    for entry in pretool:
        if not isinstance(entry, dict):
            kept_entries.append(entry)
            continue
        entry_hooks = entry.get("hooks")
        if entry.get("matcher") == "Bash" and isinstance(entry_hooks, list):
            filtered = [
                existing
                for existing in entry_hooks
                if not (isinstance(existing, dict) and existing.get("command") == handler_command)
            ]
            if len(filtered) != len(entry_hooks):
                changed = True
            if filtered:
                entry = dict(entry)
                entry["hooks"] = filtered
                kept_entries.append(entry)
        else:
            kept_entries.append(entry)

    if changed:
        if kept_entries:
            hooks["PreToolUse"] = kept_entries
        else:
            hooks.pop("PreToolUse", None)
        if hooks:
            data["hooks"] = hooks
        else:
            data.pop("hooks", None)
        _write_json(path, data)
    return changed


def _read_instructions(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    return ""


def _write_instructions(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def _contains_section(text):
    return _SECTION_HEADER in text


def _strip_section(text):
    """Remove the actx instruction section (header through blank line)."""
    lines = text.split("\n")
    out = []
    i = 0
    while i < len(lines):
        if lines[i].startswith(_SECTION_HEADER):
            i += 1
            while i < len(lines) and lines[i].strip() != "":
                i += 1
            while i < len(lines) and lines[i].strip() == "":
                i += 1
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def _append_section(text):
    """Return text with the Tier-2 instruction section appended once."""
    if _contains_section(text):
        return text
    result = text.rstrip("\n")
    if result:
        result += "\n\n"
    return result + INSTRUCTION_SECTION + "\n"


def _install_instructions(path):
    text = _read_instructions(path)
    if _contains_section(text):
        return False
    _write_instructions(path, _append_section(text))
    return True


def _uninstall_instructions(path):
    text = _read_instructions(path)
    if not _contains_section(text):
        return False
    stripped = _strip_section(text)
    _write_instructions(path, stripped.rstrip("\n") + ("\n" if stripped else ""))
    return True


def _install_opencode(path, abs_actx):
    template_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "adapters")
    template_path = os.path.join(template_dir, "opencode.ts.template")
    with open(template_path, "r", encoding="utf-8") as handle:
        template = handle.read()
    content = template.replace("__ACTX_ABS_PATH__", json.dumps(abs_actx))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return True


def _uninstall_opencode(path):
    if not os.path.exists(path):
        return False
    os.remove(path)
    return True


def _install_cursor():
    print(INSTRUCTION_SECTION, end="")
    print("Insert the section above in Cursor → Settings → Rules → User Rules.")


def _split_read_block(lines):
    """Locate and remove the ``read:`` key, returning (value, remaining_lines)."""
    value = None
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped.startswith("read:"):
            out.append(line)
            i += 1
            continue

        rest = line.split(":", 1)[1].strip()
        if not rest:
            # A read: key followed by indented list items.
            items = []
            i += 1
            while i < len(lines) and lines[i].startswith(" ") and lines[i].strip().startswith("- "):
                item = lines[i].strip()[2:].strip()
                if item:
                    items.append(item)
                i += 1
            value = items
        elif rest.startswith("[") and rest.endswith("]"):
            inner = rest[1:-1].strip()
            if inner:
                value = [part.strip() for part in inner.split(",") if part.strip()]
            else:
                value = []
        else:
            value = rest
        i += 1

    return value, out


def _read_line_for(value):
    if isinstance(value, list):
        if len(value) == 0:
            return "read: []\n"
        if len(value) == 1:
            return "read: %s\n" % value[0]
        return "read: [%s]\n" % ", ".join(value)
    return "read: %s\n" % value


def _aider_set_read(path, actx_read_path):
    """Merge the actx path into an existing scalar or list ``read:`` key."""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            original = handle.read()
    else:
        original = ""

    existing, rest = _split_read_block(original.split("\n"))
    if existing is None:
        value = actx_read_path
    elif isinstance(existing, list):
        value = list(existing)
        if actx_read_path not in value:
            value.append(actx_read_path)
    elif existing == actx_read_path:
        value = actx_read_path
    else:
        value = [existing, actx_read_path]

    rest = [line for line in rest if line.strip() != ""]
    result = "\n".join(rest).rstrip("\n")
    if result:
        result += "\n\n"
    result += _read_line_for(value)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(result)
    return True


def _install_aider(paths, abs_actx):
    instructions_path = os.path.expanduser(paths["instructions"])
    conf_path = os.path.expanduser(paths["conf"])
    os.makedirs(os.path.dirname(conf_path), exist_ok=True)
    _install_instructions(instructions_path)
    _aider_set_read(conf_path, _AIDER_READ_PATH)
    return True


def _uninstall_aider(paths):
    instructions_path = os.path.expanduser(paths["instructions"])
    conf_path = os.path.expanduser(paths["conf"])
    changed = _uninstall_instructions(instructions_path)
    if not os.path.exists(conf_path):
        return changed

    with open(conf_path, "r", encoding="utf-8") as handle:
        original = handle.read()
    existing, rest = _split_read_block(original.split("\n"))
    if existing is None:
        return changed

    value = existing
    if isinstance(value, list):
        value = [item for item in value if item != _AIDER_READ_PATH]
    elif value == _AIDER_READ_PATH:
        value = None
    else:
        return changed

    rest = [line for line in rest if line.strip() != ""]
    result = "\n".join(rest).rstrip("\n")
    if result:
        result += "\n\n"
    if value is not None:
        result += _read_line_for(value)
    result = result.rstrip("\n") + "\n"
    with open(conf_path, "w", encoding="utf-8") as handle:
        handle.write(result)
    return True


def _agent_config(agent):
    return _AGENT_PATHS[agent]


def _detect_existing(agent):
    paths = _agent_config(agent)
    if agent == "cursor":
        return False
    if agent in ("claude", "codex"):
        return os.path.exists(os.path.expanduser(os.path.dirname(paths["hook"])))
    if agent == "opencode":
        return os.path.exists(os.path.expanduser(os.path.dirname(paths["plugin"])))
    if agent == "grok":
        return os.path.exists(os.path.expanduser(paths["instructions"]))
    if agent == "cline":
        return os.path.exists(os.path.expanduser(os.path.dirname(paths["instructions"])))
    if agent == "windsurf":
        return os.path.exists(os.path.expanduser(os.path.dirname(paths["instructions"])))
    if agent == "aider":
        return os.path.exists(os.path.expanduser(paths["conf"]))
    return False


def _installed(agent):
    paths = _agent_config(agent)
    if agent == "cursor":
        return False
    if agent in ("claude", "codex"):
        path = os.path.expanduser(paths["hook"])
        if not os.path.exists(path):
            return False
        try:
            data = _read_json(path)
        except ValueError:
            return False
        if not isinstance(data, dict):
            return False
        hooks = data.get("hooks")
        if not isinstance(hooks, dict):
            return False
        pretool = hooks.get("PreToolUse")
        if not isinstance(pretool, list):
            return False
        handler_command = _hook_handler(abs_path())["command"]
        for entry in pretool:
            if isinstance(entry, dict) and entry.get("matcher") == "Bash":
                entry_hooks = entry.get("hooks")
                if isinstance(entry_hooks, list) and any(
                    isinstance(existing, dict) and existing.get("command") == handler_command
                    for existing in entry_hooks
                ):
                    return True
        return False
    if agent == "opencode":
        return os.path.exists(os.path.expanduser(paths["plugin"]))
    if agent in ("grok", "cline", "windsurf", "aider"):
        text = _read_instructions(os.path.expanduser(paths["instructions"]))
        return _contains_section(text)
    return False


def install(agent, abs_actx):
    if agent == "cursor":
        _install_cursor()
        return 0
    paths = _agent_config(agent)
    if agent in ("claude", "codex"):
        path = os.path.expanduser(paths["hook"])
        try:
            changed = _install_hook(path, abs_actx)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if agent == "opencode":
        path = os.path.expanduser(paths["plugin"])
        _install_opencode(path, abs_actx)
        return 0
    if agent in ("grok", "cline", "windsurf"):
        path = os.path.expanduser(paths["instructions"])
        _install_instructions(path)
        return 0
    if agent == "aider":
        _install_aider(paths, abs_actx)
        return 0
    print("unknown agent", file=sys.stderr)
    return 1


def uninstall(agent, abs_actx):
    if agent == "cursor":
        print("cursor has no file installation; nothing to uninstall.", file=sys.stderr)
        return 0
    paths = _agent_config(agent)
    if agent in ("claude", "codex"):
        path = os.path.expanduser(paths["hook"])
        try:
            _uninstall_hook(path, abs_actx)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if agent == "opencode":
        _uninstall_opencode(os.path.expanduser(paths["plugin"]))
        return 0
    if agent in ("grok", "cline", "windsurf"):
        _uninstall_instructions(os.path.expanduser(paths["instructions"]))
        return 0
    if agent == "aider":
        _uninstall_aider(paths)
        return 0
    print("unknown agent", file=sys.stderr)
    return 1


def show():
    for agent in AGENTS:
        if agent == "cursor":
            status = "manual (cursor)"
        else:
            status = "installed" if _installed(agent) else "not installed"
        print("%s: %s" % (agent, status))


def main(args):
    import argparse

    parser = argparse.ArgumentParser(prog="actx init", add_help=True)
    parser.add_argument("--agent", dest="agent")
    parser.add_argument("--show", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    opts = parser.parse_args(args)

    if opts.show:
        show()
        return 0

    if opts.agent is not None:
        if opts.agent == "all":
            agents = [agent for agent in AGENTS]
        elif opts.agent in AGENTS:
            agents = [opts.agent]
        else:
            print("unknown agent: %s" % opts.agent, file=sys.stderr)
            return 1
    else:
        # Auto-detection: only agents whose config locations already exist.
        agents = [agent for agent in AGENTS if agent != "cursor" and _detect_existing(agent)]

    if opts.uninstall:
        if opts.agent == "all":
            targets = [agent for agent in AGENTS]
        elif opts.agent is not None:
            targets = [opts.agent]
        elif agents:
            targets = agents
        else:
            print("no actx installation detected", file=sys.stderr)
            return 0
        for agent in targets:
            rc = uninstall(agent, abs_path())
            if rc:
                return rc
        return 0

    if not agents:
        print("no supported agent configuration found", file=sys.stderr)
        return 0

    for agent in agents:
        rc = install(agent, abs_path())
        if rc:
            return rc
    return 0
