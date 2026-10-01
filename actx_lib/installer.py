"""Adapter installer for ``actx init`` / ``--show`` / ``--uninstall``.

All adapter paths resolve through :func:`os.path.expanduser` so tests can
override ``HOME``.  The installer only merges actx entries into existing user
files; it never rewrites those files wholesale.
"""

import json
import os
import shlex
import shutil
import sys

AGENTS = (
    "claude",
    "codex",
    "opencode",
    "grok",
    "cursor",
    "cline",
    "windsurf",
    "aider",
    "gemini",
    "copilot",
    "devin",
    "pi",
)

def _tier2_flags_block():
    """Render the compact-flags conventions block; fail-open (INV-05):
    a broken render degrades to no block, never a broken init."""
    try:
        from actx_lib import conventions

        return conventions.render_tier2()
    except Exception:
        return ""


INSTRUCTION_SECTION = """## Output compression (actx)

To reduce context noise, prefix supported shell commands with `actx`:
- `git status` → `actx git status`
- `git diff` → `actx git diff`
- `git log` → `actx git log`
- `git show` / `git blame` → `actx git show` / `actx git blame`
- `ls` / `ls -la` → `actx ls` / `actx ls -la`
- `grep` / `rg` → `actx grep` / `actx rg`
- `find` / `cat` / `tree` → `actx find` / `actx cat` / `actx tree`
- `pytest` / `ruff` / `docker ps` / `gh pr list` → `actx <cmd>`
- `vercel whoami` / `railway status` / `wrangler deployments list` / `gcloud projects list` → `actx <cmd>`

Hook/plugin agents rewrite automatically when installed. For full output, run without `actx`; `actx --raw <command>` prints the raw output with secret values masked.

Package manager discipline:
- Package installations always require human confirmation (ask) — never attempt to bypass it.
- Prefer lockfile-strict forms (`npm ci` / `pnpm install --frozen-lockfile` / `uv sync --frozen`); avoid `latest`.
- Do not switch the project's package manager on your own initiative.

{TIER2_FLAGS_BLOCK}
""".format(TIER2_FLAGS_BLOCK=_tier2_flags_block())

_SECTION_HEADER = "## Output compression (actx)"

# Per-agent integration points.  cursor has no file target: install prints the
# section to stdout for manual insertion in the Cursor UI.  opencode, devin
# and pi resolve their directories from the environment (_agent_config).
_AGENT_PATHS = {
    "claude": {"hook": "~/.claude/settings.json"},
    "codex": {"hook": "~/.codex/hooks.json"},
    "grok": {"instructions": "~/.grok/rules/actx.md"},
    "cursor": {},
    "cline": {"instructions": "~/.cline/rules/actx.md"},
    "windsurf": {"instructions": "~/.codeium/windsurf/memories/global_rules.md"},
    "aider": {
        "instructions": "~/.config/actx/instructions.md",
        "conf": "~/.aider.conf.yml",
    },
    "gemini": {"hook": "~/.gemini/config/hooks.json"},
    "copilot": {"hook": "~/.copilot/settings.json"},
}

_AIDER_READ_PATH = "~/.config/actx/instructions.md"

_ADAPTERS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "adapters"
)

# Devin CLI: Claude-format PreToolUse hook; its shell tool is `exec`.
_DEVIN_MATCHER = "^exec$"


def _config_home():
    """``$XDG_CONFIG_HOME`` when set to an absolute path, else ``~/.config``
    (the XDG spec says a relative value is ignored)."""
    value = os.environ.get("XDG_CONFIG_HOME", "")
    return value if os.path.isabs(value) else "~/.config"


def _pi_agent_dir():
    """``$PI_CODING_AGENT_DIR`` when set to an absolute path (``~`` expanded),
    else ``~/.pi/agent``.  A relative value is ignored: resolving it against
    the cwd would write into a project."""
    value = os.path.expanduser(os.environ.get("PI_CODING_AGENT_DIR", ""))
    return value if os.path.isabs(value) else "~/.pi/agent"


def abs_path():
    """Return a stable absolute path to the running ``actx`` binary.

    Deliberately does NOT resolve symlinks: resolving ``/opt/homebrew/bin/actx``
    to a versioned Cellar path makes hooks break after ``brew upgrade``.
    """
    arg0 = sys.argv[0]
    if os.path.isabs(arg0):
        return arg0
    if os.sep in arg0:
        return os.path.abspath(arg0)
    found = shutil.which(arg0)
    return found or os.path.abspath(arg0)


def _is_actx_hook_command(command):
    """True only for our hook command forms: ``shlex.split`` gives exactly
    ``[<path with basename actx>, "hook"]`` or ``[<same>, "hook", "--agent",
    <name>]``.  A split failure is False."""
    if not isinstance(command, str):
        return False
    try:
        parts = shlex.split(command)
    except ValueError:
        return False
    if len(parts) not in (2, 4) or os.path.basename(parts[0]) != "actx":
        return False
    return parts[1] == "hook" and (len(parts) == 2 or parts[2] == "--agent")


def _hook_handler(abs_actx):
    return {
        "type": "command",
        "command": shlex.quote(abs_actx) + " hook",
        "timeout": 10,
    }


def _gemini_handler(abs_actx):
    return {
        "type": "command",
        "command": shlex.quote(abs_actx) + " hook",
        "timeout": 10,
    }


def _devin_handler(abs_actx):
    return {
        "type": "command",
        "command": shlex.quote(abs_actx) + " hook --agent devin",
        "timeout": 10,
    }


def _copilot_handler(abs_actx):
    return {
        "type": "command",
        "bash": shlex.quote(abs_actx) + " hook",
        "timeoutSec": 10,
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


def _install_hook(path, abs_actx, matcher="Bash"):
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
        if isinstance(entry, dict) and entry.get("matcher") in (matcher, "Bash"):
            bash_entry = entry
            if bash_entry.get("matcher") != matcher:
                bash_entry["matcher"] = matcher
                changed = True
            break

    if bash_entry is None:
        bash_entry = {"matcher": matcher, "hooks": []}
        pretool.append(bash_entry)
        changed = True

    entry_hooks = bash_entry.get("hooks")
    if not isinstance(entry_hooks, list):
        entry_hooks = []
        bash_entry["hooks"] = entry_hooks
        changed = True

    filtered = [
        existing
        for existing in entry_hooks
        if not (
            isinstance(existing, dict)
            and _is_actx_hook_command(existing.get("command"))
        )
    ]
    if len(filtered) != len(entry_hooks):
        entry_hooks = filtered
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

    changed = False
    kept_entries = []
    for entry in pretool:
        if not isinstance(entry, dict):
            kept_entries.append(entry)
            continue
        entry_hooks = entry.get("hooks")
        if entry.get("matcher") in ("Bash", "Bash|shell|bash|exec") and isinstance(entry_hooks, list):
            filtered = [
                existing
                for existing in entry_hooks
                if not (
                    isinstance(existing, dict)
                    and _is_actx_hook_command(existing.get("command"))
                )
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


def _install_gemini(path, abs_actx):
    if os.path.exists(path):
        data = _read_json(path)
        if not isinstance(data, dict):
            raise ValueError("cannot install: %s is not a JSON object" % path)
    else:
        data = {}

    actx_entry = data.get("actx-gate")
    if not isinstance(actx_entry, dict):
        actx_entry = {}

    pretool = actx_entry.get("PreToolUse")
    if not isinstance(pretool, list):
        pretool = []
    else:
        pretool = list(pretool)

    handler = _gemini_handler(abs_actx)
    command = handler["command"]
    changed = False
    cmd_entry = None
    for entry in pretool:
        if isinstance(entry, dict) and entry.get("matcher") == "run_command":
            cmd_entry = entry
            break

    if cmd_entry is None:
        cmd_entry = {"matcher": "run_command", "hooks": []}
        pretool.append(cmd_entry)
        changed = True

    entry_hooks = cmd_entry.get("hooks")
    if not isinstance(entry_hooks, list):
        entry_hooks = []
        cmd_entry["hooks"] = entry_hooks
        changed = True

    filtered = [
        existing
        for existing in entry_hooks
        if not (
            isinstance(existing, dict)
            and _is_actx_hook_command(existing.get("command"))
        )
    ]
    if len(filtered) != len(entry_hooks):
        entry_hooks = filtered
        cmd_entry["hooks"] = entry_hooks
        changed = True

    if not any(
        isinstance(existing, dict) and existing.get("command") == command
        for existing in entry_hooks
    ):
        entry_hooks.append(handler)
        changed = True

    if changed or "actx-gate" not in data:
        actx_entry["PreToolUse"] = pretool
        data["actx-gate"] = actx_entry
        _write_json(path, data)
    return changed


def _uninstall_gemini(path, abs_actx):
    if not os.path.exists(path):
        return False
    data = _read_json(path)
    if not isinstance(data, dict):
        return False

    if "actx-gate" not in data:
        return False

    data.pop("actx-gate", None)
    _write_json(path, data)
    return True


def _install_copilot(path, abs_actx):
    if os.path.exists(path):
        data = _read_json(path)
        if not isinstance(data, dict):
            raise ValueError("cannot install: %s is not a JSON object" % path)
    else:
        data = {}
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    pretool = hooks.get("preToolUse")
    if not isinstance(pretool, list):
        pretool = []
    else:
        pretool = list(pretool)

    handler = _copilot_handler(abs_actx)
    bash = handler["bash"]
    changed = False
    filtered = [
        existing
        for existing in pretool
        if not (
            isinstance(existing, dict)
            and _is_actx_hook_command(existing.get("bash"))
        )
    ]
    if len(filtered) != len(pretool):
        pretool = filtered
        changed = True
    if not any(
        isinstance(existing, dict) and existing.get("bash") == bash
        for existing in pretool
    ):
        pretool.append(handler)
        changed = True
    if changed:
        hooks["preToolUse"] = pretool
        data["hooks"] = hooks
        _write_json(path, data)
    return changed


def _uninstall_copilot(path, abs_actx):
    if not os.path.exists(path):
        return False
    data = _read_json(path)
    if not isinstance(data, dict):
        return False
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return False
    pretool = hooks.get("preToolUse")
    if not isinstance(pretool, list):
        return False
    filtered = [
        existing
        for existing in pretool
        if not (
            isinstance(existing, dict)
            and _is_actx_hook_command(existing.get("bash"))
        )
    ]
    if len(filtered) == len(pretool):
        return False
    if filtered:
        hooks["preToolUse"] = filtered
    else:
        hooks.pop("preToolUse", None)
    if hooks:
        data["hooks"] = hooks
    else:
        data.pop("hooks", None)
    _write_json(path, data)
    return True


def _devin_shape_error(data):
    """None when actx may edit this Devin config, else the reason.  A missing
    ``hooks`` / ``hooks.PreToolUse`` key is the normal create path; a key that
    is present with the wrong type is refused, never normalised."""
    if not isinstance(data, dict):
        return "the top level is not a JSON object"
    if "hooks" not in data:
        return None
    hooks = data["hooks"]
    if not isinstance(hooks, dict):
        return '"hooks" is not an object'
    if "PreToolUse" not in hooks:
        return None
    pretool = hooks["PreToolUse"]
    if not isinstance(pretool, list):
        return '"hooks.PreToolUse" is not a list'
    for entry in pretool:
        if not isinstance(entry, dict):
            return 'a "hooks.PreToolUse" entry is not an object'
        if "hooks" in entry and not isinstance(entry["hooks"], list):
            return 'a "hooks.PreToolUse" entry has "hooks" that is not a list'
    return None


def _load_devin(path):
    """The parsed Devin config ({} when the file is missing).  ValueError
    with the reason when the file must be left untouched."""
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("cannot read it as strict JSON (%s)" % exc) from exc
    reason = _devin_shape_error(data)
    if reason is not None:
        raise ValueError(reason)
    return data


def _write_devin(path, data):
    """Write in place: an existing file keeps its mode; a new one is 0600."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


def _strip_actx_handlers(pretool, keep=None):
    """Return (entries, kept): ``pretool`` without actx handlers.  An entry
    emptied by that removal is dropped; other entries and user handlers are
    returned as they were.  ``keep`` (our exact current handler) survives
    once, in the first ``^exec$`` entry holding it; ``kept`` says whether it
    did."""
    kept = False
    entries = []
    for entry in pretool:
        handlers = entry.get("hooks")
        if not isinstance(handlers, list):
            entries.append(entry)
            continue
        remaining = []
        for handler in handlers:
            if isinstance(handler, dict) and _is_actx_hook_command(handler.get("command")):
                if (keep is not None and not kept and handler == keep
                        and entry.get("matcher") == _DEVIN_MATCHER):
                    kept = True
                    remaining.append(handler)
                continue
            remaining.append(handler)
        if len(remaining) == len(handlers):
            entries.append(entry)
        elif remaining:
            entries.append(dict(entry, hooks=remaining))
    return entries, kept


def _install_devin(path, abs_actx):
    """Merge the actx handler into ``hooks.PreToolUse`` of Devin's config.
    Stale actx handlers are removed first; ours is appended to an existing
    ``^exec$`` entry or added as a new one.  Writes only on change."""
    data = _load_devin(path)
    handler = _devin_handler(abs_actx)
    hooks = data.get("hooks", {})
    pretool, kept = _strip_actx_handlers(hooks.get("PreToolUse", []), keep=handler)
    if not kept:
        for index, entry in enumerate(pretool):
            if entry.get("matcher") == _DEVIN_MATCHER and isinstance(entry.get("hooks"), list):
                pretool[index] = dict(entry, hooks=entry["hooks"] + [handler])
                break
        else:
            pretool.append({"matcher": _DEVIN_MATCHER, "hooks": [handler]})
    updated = dict(data)
    updated["hooks"] = dict(hooks, PreToolUse=pretool)
    if os.path.exists(path) and updated == data:
        return False
    _write_devin(path, updated)
    return True


def _uninstall_devin(path):
    """Remove actx handlers; drop an entry, ``PreToolUse`` or ``hooks`` only
    when that removal emptied it."""
    if not os.path.exists(path):
        return False
    data = _load_devin(path)
    hooks = data.get("hooks")
    if not hooks or "PreToolUse" not in hooks:
        return False
    pretool, _ = _strip_actx_handlers(hooks["PreToolUse"])
    if pretool == hooks["PreToolUse"]:
        return False
    updated_hooks = dict(hooks)
    if pretool:
        updated_hooks["PreToolUse"] = pretool
    else:
        del updated_hooks["PreToolUse"]
    updated = dict(data)
    if updated_hooks:
        updated["hooks"] = updated_hooks
    else:
        del updated["hooks"]
    _write_devin(path, updated)
    return True


def _devin_installed(path):
    try:
        data = _load_devin(path)
    except ValueError:
        return False
    command = _devin_handler(abs_path())["command"]
    return any(
        entry.get("matcher") == _DEVIN_MATCHER
        and any(
            isinstance(handler, dict) and handler.get("command") == command
            for handler in entry.get("hooks", [])
        )
        for entry in data.get("hooks", {}).get("PreToolUse", [])
    )


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


def _section_span(lines):
    """Return (start, end) indices of the actx section, or None.

    Section runs from its header through the line before the next Markdown
    ``## `` heading (or EOF). Internal blank lines are allowed.
    """
    start = None
    for index, line in enumerate(lines):
        if line.startswith(_SECTION_HEADER):
            start = index
            break
    if start is None:
        return None
    end = start + 1
    while end < len(lines):
        if lines[end].startswith("## ") and not lines[end].startswith(_SECTION_HEADER):
            break
        end += 1
    return start, end


def _strip_section(text):
    """Remove the actx instruction section (header through next heading/EOF)."""
    lines = text.split("\n")
    span = _section_span(lines)
    if span is None:
        return text
    start, end = span
    while end < len(lines) and lines[end].strip() == "":
        end += 1
    out = lines[:start] + lines[end:]
    return "\n".join(out)


def _section_body(text):
    """Return the actx instruction section text (rstrip), or None."""
    lines = text.split("\n")
    span = _section_span(lines)
    if span is None:
        return None
    start, end = span
    return "\n".join(lines[start:end]).rstrip("\n")


def _append_section(text):
    """Return text with the current Tier-2 instruction section (append or replace)."""
    desired = INSTRUCTION_SECTION.rstrip("\n")
    existing = _section_body(text)
    if existing == desired:
        return text
    if existing is not None:
        text = _strip_section(text)
    result = text.rstrip("\n")
    if result:
        result += "\n\n"
    return result + INSTRUCTION_SECTION + "\n"


def _install_instructions(path):
    text = _read_instructions(path)
    desired = INSTRUCTION_SECTION.rstrip("\n")
    existing = _section_body(text)
    if existing == desired:
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


def _install_template(path, template_name, abs_actx):
    """Write an actx-owned adapter file (opencode plugin, pi extension)."""
    with open(os.path.join(_ADAPTERS_DIR, template_name), "r", encoding="utf-8") as handle:
        template = handle.read()
    content = template.replace("__ACTX_ABS_PATH__", json.dumps(abs_actx))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return True


def _remove_file(path):
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
    if agent == "opencode":
        return {"plugin": os.path.join(_config_home(), "opencode", "plugins", "actx.ts")}
    if agent == "devin":
        return {"hook": os.path.join(_config_home(), "devin", "config.json")}
    if agent == "pi":
        return {"plugin": os.path.join(_pi_agent_dir(), "extensions", "actx.ts")}
    return _AGENT_PATHS[agent]


def _detect_existing(agent):
    paths = _agent_config(agent)
    if agent == "cursor":
        return False
    if agent in ("claude", "codex", "gemini", "copilot", "devin"):
        return os.path.exists(os.path.expanduser(os.path.dirname(paths["hook"])))
    if agent == "opencode":
        return os.path.exists(os.path.expanduser(os.path.dirname(paths["plugin"])))
    if agent == "pi":
        return os.path.isdir(os.path.expanduser(_pi_agent_dir()))
    if agent == "grok":
        return os.path.isdir(os.path.expanduser("~/.grok"))
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
            if isinstance(entry, dict) and entry.get("matcher") in ("Bash", "Bash|shell|bash|exec"):
                entry_hooks = entry.get("hooks")
                if isinstance(entry_hooks, list) and any(
                    isinstance(existing, dict) and existing.get("command") == handler_command
                    for existing in entry_hooks
                ):
                    return True
        return False
    if agent == "gemini":
        path = os.path.expanduser(paths["hook"])
        if not os.path.exists(path):
            return False
        try:
            data = _read_json(path)
        except ValueError:
            return False
        if not isinstance(data, dict):
            return False
        actx_entry = data.get("actx-gate")
        if not isinstance(actx_entry, dict):
            return False
        pretool = actx_entry.get("PreToolUse")
        if not isinstance(pretool, list):
            return False
        command = _gemini_handler(abs_path())["command"]
        for entry in pretool:
            if isinstance(entry, dict) and entry.get("matcher") == "run_command":
                entry_hooks = entry.get("hooks")
                if isinstance(entry_hooks, list) and any(
                    isinstance(existing, dict)
                    and existing.get("command") == command
                    for existing in entry_hooks
                ):
                    return True
        return False
    if agent == "copilot":
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
        pretool = hooks.get("preToolUse")
        if not isinstance(pretool, list):
            return False
        bash = _copilot_handler(abs_path())["bash"]
        return any(
            isinstance(existing, dict) and existing.get("bash") == bash
            for existing in pretool
        )
    if agent in ("opencode", "pi"):
        return os.path.exists(os.path.expanduser(paths["plugin"]))
    if agent == "devin":
        return _devin_installed(os.path.expanduser(paths["hook"]))
    if agent in ("grok", "cline", "windsurf", "aider"):
        text = _read_instructions(os.path.expanduser(paths["instructions"]))
        return _contains_section(text)
    return False


def install(agent, abs_actx):
    if agent == "cursor":
        _install_cursor()
        return 0
    paths = _agent_config(agent)
    if agent == "claude":
        path = os.path.expanduser(paths["hook"])
        try:
            changed = _install_hook(path, abs_actx, matcher="Bash")
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if agent == "codex":
        path = os.path.expanduser(paths["hook"])
        try:
            changed = _install_hook(path, abs_actx, matcher="Bash|shell|bash|exec")
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if agent == "gemini":
        path = os.path.expanduser(paths["hook"])
        try:
            _install_gemini(path, abs_actx)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if agent == "copilot":
        path = os.path.expanduser(paths["hook"])
        try:
            _install_copilot(path, abs_actx)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if agent in ("opencode", "pi"):
        path = os.path.expanduser(paths["plugin"])
        _install_template(path, "%s.ts.template" % agent, abs_actx)
        return 0
    if agent == "devin":
        path = os.path.expanduser(paths["hook"])
        try:
            _install_devin(path, abs_actx)
        except ValueError as exc:
            entry = {"matcher": _DEVIN_MATCHER, "hooks": [_devin_handler(abs_actx)]}
            print(
                "cannot install: %s: %s. The file may contain comments or an "
                "unexpected shape; it was left unchanged. Add this entry to the "
                '"hooks.PreToolUse" list manually:\n%s'
                % (path, exc, json.dumps(entry, indent=2)),
                file=sys.stderr,
            )
            return 1
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
    if agent == "gemini":
        path = os.path.expanduser(paths["hook"])
        try:
            _uninstall_gemini(path, abs_actx)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if agent == "copilot":
        path = os.path.expanduser(paths["hook"])
        try:
            _uninstall_copilot(path, abs_actx)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if agent in ("opencode", "pi"):
        _remove_file(os.path.expanduser(paths["plugin"]))
        return 0
    if agent == "devin":
        path = os.path.expanduser(paths["hook"])
        try:
            _uninstall_devin(path)
        except ValueError as exc:
            print(
                "cannot uninstall: %s: %s. The file may contain comments or an "
                "unexpected shape; it was left unchanged. Remove the actx "
                "handler (command ending in \"hook --agent devin\") manually."
                % (path, exc),
                file=sys.stderr,
            )
            return 1
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
    parser.add_argument(
        "--agent",
        dest="agent",
        help="one of: %s, all (default: agents whose config exists)" % ", ".join(AGENTS),
    )
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
