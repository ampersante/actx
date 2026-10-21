"""Adapter installer for ``actx init`` / ``--show`` / ``--uninstall``.

All adapter paths resolve through :func:`os.path.expanduser` so tests can
override ``HOME``.  The installer only merges actx entries into existing user
files; it never rewrites those files wholesale.
"""

import json
import os
import shlex
import shutil
import stat
import sys
import tempfile

AGENTS = (
    "claude",
    "codex",
    "opencode",
    "grok",
    "cursor",
    "cline",
    "windsurf",
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
    "gemini": {"hook": "~/.gemini/config/hooks.json"},
    "copilot": {"hook": "~/.copilot/settings.json"},
}

_ADAPTERS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "adapters"
)

# Devin CLI: Claude-format PreToolUse hook; its shell tool is `exec`.
_DEVIN_MATCHER = "^exec$"

# Codex names its shell tool differently across versions.
_CODEX_MATCHER = "Bash|shell|bash|exec"


class _FileError(Exception):
    """A user file actx cannot read or write.  ``main`` reports it as
    ``actx init: cannot <op> <path>: <reason>`` and exits 1; the file is
    untouched."""

    def __init__(self, op, path, reason):
        super().__init__("cannot %s %s: %s" % (op, path, reason))
        self.op = op
        self.path = path
        self.reason = reason


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


def _read_text(path):
    """The file's text with its line endings untouched."""
    try:
        with open(path, "r", encoding="utf-8", newline="") as handle:
            return handle.read()
    except UnicodeDecodeError as exc:
        raise _FileError("read", path, "not valid UTF-8 (%s)" % exc.reason) from exc
    except OSError as exc:
        raise _FileError("read", path, exc.strerror or str(exc)) from exc


def _write_text(path, text):
    """Replace ``path`` atomically (temp file in the same directory, then
    ``os.replace``).  A symlink keeps pointing where it did and its target is
    written, a dangling one included.  An existing file keeps its mode, a new
    one is 0600.  An existing target that is not writable is refused rather
    than replaced.  Known limit: replacing breaks hard links and drops
    xattrs/ACLs."""
    target = os.path.realpath(path)
    directory = os.path.dirname(target)
    try:
        os.makedirs(directory, exist_ok=True)
        if os.path.exists(target):
            if not os.access(target, os.W_OK):
                raise PermissionError(13, "Permission denied")
            mode = stat.S_IMODE(os.stat(target).st_mode)
        else:
            mode = 0o600
        fd, temp = tempfile.mkstemp(dir=directory, prefix=".actx-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
            os.chmod(temp, mode)
            os.replace(temp, target)
        except BaseException:
            try:
                os.unlink(temp)
            except OSError:
                pass
            raise
    except OSError as exc:
        raise _FileError("write", path, exc.strerror or str(exc)) from exc


def _read_json(path):
    text = _read_text(path)
    try:
        return json.loads(text)
    except ValueError as exc:
        raise ValueError("cannot parse JSON at %s" % path) from exc


def _write_json(path, data):
    _write_text(path, json.dumps(data, indent=2) + "\n")


def _is_actx_handler(handler):
    return isinstance(handler, dict) and _is_actx_hook_command(handler.get("command"))


def _load_hook_settings(path):
    """The parsed Claude/Codex-style settings ({} when the file is missing).
    ValueError when the file must be left untouched: unparseable, or a
    ``hooks`` / ``hooks.PreToolUse`` value of the wrong type that a merge
    would overwrite."""
    if not os.path.exists(path):
        return {}
    data = _read_json(path)
    if not isinstance(data, dict):
        raise ValueError("cannot install: %s is not a JSON object" % path)
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError('cannot install: "hooks" in %s is not an object' % path)
    if "PreToolUse" in hooks and not isinstance(hooks["PreToolUse"], list):
        raise ValueError('cannot install: "hooks.PreToolUse" in %s is not a list' % path)
    return data


def _install_hook(path, abs_actx):
    """Claude: merge the actx handler into the user's exact ``Bash`` entry
    (PRD 6.4); its matcher is never changed."""
    data = _load_hook_settings(path)
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
    pretool = hooks.get("PreToolUse")
    pretool = list(pretool) if isinstance(pretool, list) else []

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

    filtered = [existing for existing in entry_hooks if not _is_actx_handler(existing)]
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


def _install_codex(path, abs_actx):
    """Codex: actx's entry is found by its handler command, never by matcher,
    so a user's own entry keeps its matcher and handlers.  Stale actx handlers
    are removed from every entry; ours is kept or added by ``_merge_pretool``."""
    data = _load_hook_settings(path)
    pretool = (data.get("hooks") or {}).get("PreToolUse", [])
    shared = [
        entry
        for entry in pretool
        if isinstance(entry, dict)
        and entry.get("matcher") == _CODEX_MATCHER
        and isinstance(entry.get("hooks"), list)
        and any(_is_actx_handler(h) for h in entry["hooks"])
        and any(not _is_actx_handler(h) for h in entry["hooks"])
    ]
    changed = _merge_pretool(path, data, _hook_handler(abs_actx), _CODEX_MATCHER)
    if shared:
        print(
            "note: %s: an entry with matcher %r also holds other hooks; its "
            "matcher was left unchanged (an earlier actx may have widened it)."
            % (path, _CODEX_MATCHER)
        )
    if changed:
        print("codex: hook entry written; trust it again via /hooks in Codex.")
    return changed


def _uninstall_hook(path):
    """Claude/Codex: remove only actx handlers (found by command, in any
    entry); an entry or ``PreToolUse`` or ``hooks`` is dropped only when that
    removal emptied it."""
    if not os.path.exists(path):
        return False
    data = _read_json(path)
    if not isinstance(data, dict):
        return False
    return _remove_pretool(path, data)


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


def _strip_actx_handlers(pretool, matcher=None, keep=None):
    """Return (entries, kept): ``pretool`` without actx handlers.  An entry
    emptied by that removal is dropped; other entries and user handlers are
    returned as they were.  ``keep`` (our exact current handler) survives
    once, in the first entry whose matcher is ``matcher`` that holds it;
    ``kept`` says whether it did."""
    kept = False
    entries = []
    for entry in pretool:
        handlers = entry.get("hooks") if isinstance(entry, dict) else None
        if not isinstance(handlers, list):
            entries.append(entry)
            continue
        remaining = []
        for handler in handlers:
            if _is_actx_handler(handler):
                if (keep is not None and not kept and handler == keep
                        and entry.get("matcher") == matcher):
                    kept = True
                    remaining.append(handler)
                continue
            remaining.append(handler)
        if len(remaining) == len(handlers):
            entries.append(entry)
        elif remaining:
            entries.append(dict(entry, hooks=remaining))
    return entries, kept


def _merge_pretool(path, data, handler, matcher):
    """Merge ``handler`` into ``hooks.PreToolUse`` of the parsed settings
    ``data``: stale actx handlers are removed first; ours is appended to an
    existing ``matcher`` entry or added as a new one.  Writes only on change."""
    hooks = data.get("hooks", {})
    pretool, kept = _strip_actx_handlers(
        hooks.get("PreToolUse", []), matcher, keep=handler
    )
    if not kept:
        for index, entry in enumerate(pretool):
            if (isinstance(entry, dict) and entry.get("matcher") == matcher
                    and isinstance(entry.get("hooks"), list)):
                pretool[index] = dict(entry, hooks=entry["hooks"] + [handler])
                break
        else:
            pretool.append({"matcher": matcher, "hooks": [handler]})
    updated = dict(data)
    updated["hooks"] = dict(hooks, PreToolUse=pretool)
    if os.path.exists(path) and updated == data:
        return False
    _write_json(path, updated)
    return True


def _remove_pretool(path, data):
    """Remove actx handlers from the parsed settings ``data`` and write the
    file; drop an entry, ``PreToolUse`` or ``hooks`` only when that removal
    emptied it.  False when nothing changed."""
    hooks = data.get("hooks")
    if not isinstance(hooks, dict) or not isinstance(hooks.get("PreToolUse"), list):
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
    _write_json(path, updated)
    return True


def _install_devin(path, abs_actx):
    """Devin: ``_merge_pretool`` into its ``^exec$`` entry."""
    return _merge_pretool(path, _load_devin(path), _devin_handler(abs_actx), _DEVIN_MATCHER)


def _uninstall_devin(path):
    if not os.path.exists(path):
        return False
    return _remove_pretool(path, _load_devin(path))


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
    return _read_text(path) if os.path.exists(path) else ""


def _contains_section(text):
    return _section_span(text.split("\n")) is not None


def _is_section_header(line):
    """The exact header line; a trailing CR or spaces are tolerated, a longer
    heading that merely starts with it is not our section."""
    return line.rstrip() == _SECTION_HEADER


def _section_span(lines):
    """Return (start, end) indices of the actx section, or None.

    Section runs from its header through the line before the next Markdown
    ``## `` heading that is not that header (or EOF). Internal blank lines are
    allowed.
    """
    start = None
    for index, line in enumerate(lines):
        if _is_section_header(line):
            start = index
            break
    if start is None:
        return None
    end = start + 1
    while end < len(lines):
        if lines[end].startswith("## ") and not _is_section_header(lines[end]):
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
    """Return the actx instruction section text (rstrip, CR-free), or None."""
    lines = text.split("\n")
    span = _section_span(lines)
    if span is None:
        return None
    start, end = span
    return "\n".join(line.rstrip("\r") for line in lines[start:end]).rstrip("\n")


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
    _write_text(path, _append_section(text))
    return True


def _uninstall_instructions(path):
    text = _read_instructions(path)
    if not _contains_section(text):
        return False
    stripped = _strip_section(text)
    _write_text(path, stripped.rstrip("\n") + ("\n" if stripped else ""))
    return True


def _install_template(path, template_name, abs_actx):
    """Write an actx-owned adapter file (opencode plugin, pi extension)."""
    template = _read_text(os.path.join(_ADAPTERS_DIR, template_name))
    _write_text(path, template.replace("__ACTX_ABS_PATH__", json.dumps(abs_actx)))
    return True


def _remove_file(path):
    if not os.path.exists(path):
        return False
    try:
        os.remove(path)
    except OSError as exc:
        raise _FileError("write", path, exc.strerror or str(exc)) from exc
    return True


def _install_cursor():
    print(INSTRUCTION_SECTION, end="")
    print("Insert the section above in Cursor → Settings → Rules → User Rules.")


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
        return any(
            isinstance(entry, dict)
            and isinstance(entry.get("hooks"), list)
            and any(
                isinstance(existing, dict) and existing.get("command") == handler_command
                for existing in entry["hooks"]
            )
            for entry in pretool
        )
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
    if agent in ("grok", "cline", "windsurf"):
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
            _install_hook(path, abs_actx)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if agent == "codex":
        path = os.path.expanduser(paths["hook"])
        try:
            _install_codex(path, abs_actx)
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
            _uninstall_hook(path)
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
    print("unknown agent", file=sys.stderr)
    return 1


def show():
    for agent in AGENTS:
        if agent == "cursor":
            status = "manual (cursor)"
        else:
            try:
                status = "installed" if _installed(agent) else "not installed"
            except _FileError:
                status = "unreadable"
        print("%s: %s" % (agent, status))


def _run_agent(action, agent):
    """Run ``install`` / ``uninstall`` for one agent; an unreadable or
    unwritable user file becomes one stderr line and rc 1, never a traceback."""
    try:
        return action(agent, abs_path())
    except _FileError as exc:
        print("actx init: %s" % exc, file=sys.stderr)
        return 1


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
        failed = [agent for agent in targets if _run_agent(uninstall, agent)]
        return 1 if failed else 0

    if not agents:
        print("no supported agent configuration found", file=sys.stderr)
        return 0

    failed = [agent for agent in agents if _run_agent(install, agent)]
    return 1 if failed else 0
