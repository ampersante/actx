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
import subprocess
import sys
import tempfile
import urllib.parse

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
    "dsh",
    "hermes",
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

# dsh reads `cordis.patch.yml` as YAML; actx writes it as JSON (JSON is a
# subset of YAML), so everything else in it stays byte-identical.
_DSH_HOME = "~/.dsh"


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
    if changed:
        if shared:
            print(
                "note: %s: an entry with matcher %r also holds other hooks; "
                "its matcher was left unchanged (an earlier actx may have "
                "widened it)." % (path, _CODEX_MATCHER)
            )
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


def _dsh_name_target(name, patch_path):
    """The filesystem path an entry's ``name`` denotes, or None.  dsh resolves
    a relative name next to the patch file and reads ``file://`` URLs as its
    normalized form; both spellings are accepted."""
    if not isinstance(name, str) or not name:
        return None
    if name.startswith("file://"):
        name = urllib.parse.unquote(name[len("file://"):])
    name = os.path.expanduser(name)
    if not os.path.isabs(name):
        name = os.path.join(os.path.dirname(patch_path), name)
    return name


def _dsh_entry_is_ours(entry, patch_path, mjs_path):
    """An entry is ours only when ``id == "actx"`` and ``name`` resolves to
    our mjs.  A foreign entry that merely shares the id is not ours."""
    if not isinstance(entry, dict) or entry.get("id") != "actx":
        return False
    target = _dsh_name_target(entry.get("name"), patch_path)
    if target is None:
        return False
    return os.path.realpath(target) == os.path.realpath(mjs_path)


def _dsh_row_is_ours(row, patch_path, mjs_path):
    """A patch-list item is ours in two shapes:

    - the insert operation actx writes: a dict whose ``insert`` holds exactly
      one entry that is ours (a foreign insert operation is never ours);
    - the legacy plain-entry form written before the patch-operation shape was
      known (dsh read it as an override that matched nothing and dropped it):
      the entry itself, so re-init and uninstall clean such an installation up.

    A foreign override operation (an item with our id but no insert) is not
    ours and stays untouched."""
    if not isinstance(row, dict):
        return False
    if "insert" in row:
        entries = row["insert"]
        return (
            isinstance(entries, list)
            and len(entries) == 1
            and _dsh_entry_is_ours(entries[0], patch_path, mjs_path)
        )
    return _dsh_entry_is_ours(row, patch_path, mjs_path)


def _dsh_row():
    """The canonical patch item: a new entry goes in through ``insert`` (a
    bare ``{"id": ...}`` item is an override of an existing entry)."""
    return {"insert": [{"id": "actx", "name": "./actx/actx-dsh.mjs"}]}


def _load_dsh_patch(path):
    """The parsed patch items ([] when the file is missing).  ValueError with
    the reason when the file must be left untouched: a hand-written YAML
    patch is refused, never normalized (the Devin canon)."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("cannot read it as strict JSON (%s)" % exc) from exc
    if not isinstance(data, list):
        raise ValueError("the top level is not a JSON array")
    for row in data:
        if not isinstance(row, dict):
            raise ValueError("a patch item is not a JSON object")
    return data


def _merge_dsh_patch(path, mjs_path):
    """Merge our insert operation into the patch list: foreign items keep their
    order and content, our items (either shape) are replaced by the canonical
    one.  Writes only on change."""
    rows = _load_dsh_patch(path)
    merged = [row for row in rows if not _dsh_row_is_ours(row, path, mjs_path)]
    merged.append(_dsh_row())
    if merged == rows:
        return False
    _write_json(path, merged)
    return True


def _remove_dsh_patch(path, mjs_path):
    """Remove our items (either shape); the file is deleted when nothing else
    was there.  False when there is nothing to remove."""
    if not os.path.exists(path):
        return False
    rows = _load_dsh_patch(path)
    remaining = [row for row in rows if not _dsh_row_is_ours(row, path, mjs_path)]
    if len(remaining) == len(rows):
        return False
    if remaining:
        _write_json(path, remaining)
    else:
        _remove_file(path)
    return True


def _dsh_installed(paths):
    """Both halves of the installation: the mjs exists and the patch parses
    with our insert operation among its items.  A file actx cannot parse reads
    as not installed, never as an error."""
    mjs = os.path.expanduser(paths["plugin"])
    patch = os.path.expanduser(paths["patch"])
    if not os.path.exists(mjs):
        return False
    try:
        rows = _load_dsh_patch(patch)
    except ValueError:
        return False
    return any(_dsh_row_is_ours(row, patch, mjs) for row in rows)


# Hermes Agent (TK-69): actx registers a `pre_tool_call` shell hook through
# the hermes CLI and pre-approves it in the profile's
# `shell-hooks-allowlist.json`.  Both sides key on one command string, built
# once per run.  A cold first CLI call bootstraps an isolated runtime
# (~91 s measured), hence the generous timeout.
_HERMES_HOME = "~/.hermes"
_HERMES_TIMEOUT = 120
_HERMES_MATCHER = "^terminal$"
# The default profile takes no `-p` flag; this sentinel names it internally.
_HERMES_DEFAULT_PROFILE = "default-profile"


class _HermesProfileError(Exception):
    """One Hermes profile whose state actx cannot read or write safely.  The
    run keeps processing the other profiles and exits 1 at the end."""


def _hermes_binary():
    """The single hermes resolution point (tests mock this helper)."""
    return shutil.which("hermes")


def _hermes_home_exists():
    return os.path.isdir(os.path.expanduser(_HERMES_HOME))


def _hermes_gate():
    """(binary, None) when the hermes CLI may be run, else (None, note).  No
    subprocess is spawned before this gate passes: a home without Hermes
    keeps `actx init --agent all` offline and test-hermetic."""
    if not _hermes_home_exists():
        return None, "no ~/.hermes data root - skipping (run hermes once first)"
    binary = _hermes_binary()
    if binary is None:
        return None, "the hermes binary was not found on PATH - skipping"
    return binary, None


def _hermes_command(abs_actx):
    return shlex.quote(abs_actx) + " hook --agent hermes"


def _hermes_entry(command):
    return {
        "command": command,
        "matcher": _HERMES_MATCHER,
        "timeout": 10,
        "fail_closed": True,
    }


def _hermes_label(profile):
    if profile == _HERMES_DEFAULT_PROFILE:
        return "default profile"
    return "profile %r" % (profile,)


def _hermes_profiles():
    """The default profile plus each configured extra, in order, deduped.
    A non-list value or a non-string entry is noted and ignored."""
    profiles = [_HERMES_DEFAULT_PROFILE]
    try:
        from actx_lib import config

        configured = config.load().get("hermes_profiles")
    except Exception as exc:
        print(
            "actx init: hermes: cannot read the actx config (%s); only the "
            "default profile is used" % exc,
            file=sys.stderr,
        )
        return profiles
    if not isinstance(configured, list):
        print(
            'actx init: hermes: config "hermes_profiles" is not a list - ignored',
            file=sys.stderr,
        )
        return profiles
    for name in configured:
        if not isinstance(name, str) or not name:
            print(
                'actx init: hermes: config "hermes_profiles" entry %r is not a '
                "profile name - ignored" % (name,),
                file=sys.stderr,
            )
            continue
        if name not in profiles:
            profiles.append(name)
    return profiles


def _hermes_argv(binary, profile, *args):
    """One `hermes config` argv; the default profile passes no `-p` flag."""
    prefix = [] if profile == _HERMES_DEFAULT_PROFILE else ["-p", profile]
    return [binary] + prefix + ["config"] + list(args)


def _run_hermes(binary, profile, args, label):
    """Run one `hermes config` verb and return stdout.  A spawn failure, a
    timeout or a non-zero exit is a profile error, never a traceback
    (exec-array only, engineering rule 3)."""
    argv = _hermes_argv(binary, profile, *args)
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=_HERMES_TIMEOUT
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _HermesProfileError(
            "%s: cannot run %s: %s" % (label, " ".join(argv), exc)
        ) from exc
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        raise _HermesProfileError(
            "%s: `hermes %s` exited %d%s"
            % (label, " ".join(args), proc.returncode,
               ": " + detail[0] if detail else "")
        )
    return proc.stdout


def _hermes_get_hooks(binary, profile, label):
    stdout = _run_hermes(binary, profile, ("get", "hooks", "--json"), label)
    try:
        hooks = json.loads(stdout)
    except ValueError as exc:
        raise _HermesProfileError(
            "%s: `hermes config get hooks --json` did not return JSON (%s)"
            % (label, exc)
        ) from exc
    if not isinstance(hooks, dict):
        raise _HermesProfileError(
            "%s: `hermes config get hooks --json` returned no JSON object"
            % label
        )
    return hooks


def _hermes_config_home(binary, profile, label):
    """The profile's home: the directory of its `hermes config path` file."""
    stdout = _run_hermes(binary, profile, ("path",), label)
    lines = stdout.splitlines()
    path = lines[0].strip() if lines else ""
    home = os.path.dirname(os.path.expanduser(path)) if path else ""
    if not home:
        raise _HermesProfileError(
            "%s: `hermes config path` printed no config path" % label
        )
    return home


def _load_hermes_allowlist(path):
    """The parsed allowlist ({"approvals": []} when the file is missing).
    ValueError with the reason when the file must be left untouched."""
    if not os.path.exists(path):
        return {"approvals": []}
    try:
        data = _read_json(path)
    except (_FileError, ValueError) as exc:
        raise ValueError(str(exc)) from exc
    if not isinstance(data, dict):
        raise ValueError("%s is not a JSON object" % path)
    if "approvals" not in data:
        return data
    approvals = data["approvals"]
    if not isinstance(approvals, list) or not all(
        isinstance(approval, dict) for approval in approvals
    ):
        raise ValueError('%s: "approvals" is not a list of objects' % path)
    return data


def _is_actx_hermes_entry(entry):
    return isinstance(entry, dict) and _is_actx_hook_command(entry.get("command"))


def _merge_hermes_hooks(hooks, command):
    """The hooks object with actx entries replaced by the current one; foreign
    entries keep order and content.  ValueError when `pre_tool_call` has a
    shape a merge would overwrite."""
    entries = hooks.get("pre_tool_call", [])
    if not isinstance(entries, list):
        raise ValueError('"pre_tool_call" is not a list')
    kept = [entry for entry in entries if not _is_actx_hermes_entry(entry)]
    if not any(
        isinstance(entry, dict) and entry.get("command") == command
        for entry in kept
    ):
        kept.append(_hermes_entry(command))
    merged = dict(hooks)
    merged["pre_tool_call"] = kept
    return merged


def _merge_hermes_allowlist(data, command):
    """The allowlist with actx approvals replaced by the current one; foreign
    approvals keep order and content."""
    approvals = data.get("approvals", [])
    kept = [approval for approval in approvals if not _is_actx_hermes_entry(approval)]
    if not any(approval.get("command") == command for approval in kept):
        kept.append({"event": "pre_tool_call", "command": command})
    merged = dict(data)
    merged["approvals"] = kept
    return merged


def _remove_hermes_hooks(hooks):
    """The hooks object without actx entries, or None when there were none."""
    entries = hooks.get("pre_tool_call", [])
    if not isinstance(entries, list):
        raise ValueError('"pre_tool_call" is not a list')
    kept = [entry for entry in entries if not _is_actx_hermes_entry(entry)]
    if kept == entries:
        return None
    merged = dict(hooks)
    merged["pre_tool_call"] = kept
    return merged


def _remove_hermes_approvals(data):
    """The allowlist without actx approvals, or None when there were none."""
    approvals = data.get("approvals", [])
    kept = [approval for approval in approvals if not _is_actx_hermes_entry(approval)]
    if kept == approvals:
        return None
    merged = dict(data)
    merged["approvals"] = kept
    return merged


def _hermes_has_content(data):
    """True when the dict holds anything besides empty containers."""
    for value in data.values():
        if isinstance(value, (dict, list)):
            if value:
                return True
        elif value is not None and value != "" and value is not False:
            return True
    return False


def _hermes_set_hook_key(binary, profile, key, value, label):
    """Write one sub-key of the `hooks` section through its dotted path.  The
    whole section cannot be set: the CLI refuses a list where it expects a
    section's sub-key map (found live, CHK-08)."""
    _run_hermes(
        binary, profile,
        ("set", "hooks.%s" % (key,), json.dumps(value, separators=(",", ":"))),
        label,
    )


def _hermes_unset_path(binary, profile, path, label):
    """Remove one configuration path (`hooks` or `hooks.<key>`) whole."""
    _run_hermes(binary, profile, ("unset", path), label)


def _hermes_write_changed_hooks(binary, profile, fetched, merged, label):
    """One dotted `set` per sub-key whose value differs from the fetched
    hooks; a sub-key actx did not change is never rewritten."""
    for key, value in merged.items():
        if key not in fetched or fetched[key] != value:
            _hermes_set_hook_key(binary, profile, key, value, label)


def _hermes_write_removed_hooks(binary, profile, hooks, label):
    """Drop actx's entries from the hooks section: our entries are already
    gone from `hooks`.  A surviving list keeps its foreign entries through
    one dotted set; an emptied list is unset, never written back; a section
    left with no content is unset whole.  Foreign sub-keys are never
    written."""
    entries = hooks.get("pre_tool_call")
    if entries:
        _hermes_set_hook_key(binary, profile, "pre_tool_call", entries, label)
    elif _hermes_has_content(hooks):
        _hermes_unset_path(binary, profile, "hooks.pre_tool_call", label)
    else:
        _hermes_unset_path(binary, profile, "hooks", label)


def _install_hermes_profile(binary, profile, command):
    label = _hermes_label(profile)
    hooks = _hermes_get_hooks(binary, profile, label)
    home = _hermes_config_home(binary, profile, label)
    allowlist_path = os.path.join(home, "shell-hooks-allowlist.json")
    # Both user-owned sides are validated before the first write (F5/C5): a
    # refused side leaves both byte-identical, never a half-install.
    try:
        allowlist = _load_hermes_allowlist(allowlist_path)
    except ValueError as exc:
        raise _HermesProfileError(
            "%s: %s; nothing was written" % (label, exc)
        ) from exc
    try:
        merged_hooks = _merge_hermes_hooks(hooks, command)
    except ValueError as exc:
        raise _HermesProfileError(
            "%s: hooks %s; nothing was written" % (label, exc)
        ) from exc
    merged_allowlist = _merge_hermes_allowlist(allowlist, command)
    _hermes_write_changed_hooks(binary, profile, hooks, merged_hooks, label)
    if merged_allowlist != allowlist:
        try:
            _write_json(allowlist_path, merged_allowlist)
        except _FileError as exc:
            raise _HermesProfileError("%s: %s" % (label, exc)) from exc


def _install_hermes(abs_actx):
    binary, skip = _hermes_gate()
    if binary is None:
        print("actx init: hermes: %s" % skip, file=sys.stderr)
        return 0
    command = _hermes_command(abs_actx)
    failed = 0
    for profile in _hermes_profiles():
        try:
            _install_hermes_profile(binary, profile, command)
        except _HermesProfileError as exc:
            print("actx init: hermes: %s" % exc, file=sys.stderr)
            failed += 1
    if failed:
        raise _FileError(
            "install", "hermes",
            "%d profile(s) failed; the notes above name each one" % failed,
        )
    return 0


def _uninstall_hermes_profile(binary, profile, command):
    label = _hermes_label(profile)
    try:
        hooks = _hermes_get_hooks(binary, profile, label)
        home = _hermes_config_home(binary, profile, label)
    except _HermesProfileError as exc:
        raise _HermesProfileError(
            "%s. Nothing was changed; remove the entry whose command is %r "
            "manually." % (exc, command)
        ) from exc
    allowlist_path = os.path.join(home, "shell-hooks-allowlist.json")
    try:
        allowlist = _load_hermes_allowlist(allowlist_path)
    except ValueError as exc:
        raise _HermesProfileError(
            "%s: %s. Nothing was written; remove the approvals whose command "
            "is %r manually." % (label, exc, command)
        ) from exc
    try:
        reduced_hooks = _remove_hermes_hooks(hooks)
    except ValueError as exc:
        raise _HermesProfileError(
            "%s: hooks %s. The hook config was left unchanged; remove the "
            "entry whose command is %r manually." % (label, exc, command)
        ) from exc
    reduced_allowlist = _remove_hermes_approvals(allowlist)
    if reduced_hooks is not None:
        _hermes_write_removed_hooks(binary, profile, reduced_hooks, label)
    if reduced_allowlist is not None:
        try:
            if _hermes_has_content(reduced_allowlist):
                _write_json(allowlist_path, reduced_allowlist)
            else:
                _remove_file(allowlist_path)
        except _FileError as exc:
            raise _HermesProfileError("%s: %s" % (label, exc)) from exc


def _uninstall_hermes(abs_actx):
    binary, skip = _hermes_gate()
    if binary is None:
        print("actx init: hermes: %s" % skip, file=sys.stderr)
        return 0
    command = _hermes_command(abs_actx)
    failed = 0
    for profile in _hermes_profiles():
        try:
            _uninstall_hermes_profile(binary, profile, command)
        except _HermesProfileError as exc:
            print("actx init: hermes: %s" % exc, file=sys.stderr)
            failed += 1
    if failed:
        raise _FileError(
            "uninstall", "hermes",
            "%d profile(s) failed; the notes above name each one" % failed,
        )
    return 0


def _hermes_installed():
    """True iff the default profile's allowlist names the exact current hook
    command.  A stdlib read: `--show` never runs the hermes CLI."""
    path = os.path.join(
        os.path.expanduser(_HERMES_HOME), "shell-hooks-allowlist.json"
    )
    try:
        data = _read_json(path)
    except (_FileError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    approvals = data.get("approvals")
    if not isinstance(approvals, list):
        return False
    command = _hermes_command(abs_path())
    return any(
        isinstance(approval, dict) and approval.get("command") == command
        for approval in approvals
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
    """Write an actx-owned adapter file (opencode plugin, pi extension, dsh
    plugin)."""
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
    if agent == "dsh":
        # dsh has no documented home override (the shipped bundle has no
        # reader of a $DSH_HOME-style variable), so the home is the literal
        # ~/.dsh; an override needs a cited reader first.
        dsh_home = os.path.expanduser(_DSH_HOME)
        return {
            "plugin": os.path.join(dsh_home, "actx", "actx-dsh.mjs"),
            "patch": os.path.join(dsh_home, "cordis.patch.yml"),
        }
    if agent == "hermes":
        # The hermes CLI owns its config files; dispatch by name only.
        return {}
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
    if agent == "dsh":
        return os.path.isdir(os.path.expanduser(_DSH_HOME))
    if agent == "hermes":
        return _hermes_home_exists()
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
    if agent == "dsh":
        return _dsh_installed(paths)
    if agent == "hermes":
        return _hermes_installed()
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
    if agent == "dsh":
        # The mjs is actx-owned and inert on its own (dsh loads only what the
        # patch names), so it is written first: a refused patch leaves an
        # unused file that --show reads as not installed and uninstall removes.
        mjs = os.path.expanduser(paths["plugin"])
        _install_template(mjs, "dsh.mjs.template", abs_actx)
        patch = os.path.expanduser(paths["patch"])
        try:
            _merge_dsh_patch(patch, mjs)
        except ValueError as exc:
            print(
                "cannot install: %s: %s. The file may be a hand-written YAML "
                "patch; it was left unchanged. Add this insert operation to "
                "the JSON array manually:\n%s"
                % (patch, exc, json.dumps([_dsh_row()], indent=2)),
                file=sys.stderr,
            )
            return 1
        return 0
    if agent == "hermes":
        return _install_hermes(abs_actx)
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
    if agent == "dsh":
        # The patch row goes first: a refused patch leaves the mjs in place,
        # so a dsh boot never misses a plugin the patch still names.
        mjs = os.path.expanduser(paths["plugin"])
        patch = os.path.expanduser(paths["patch"])
        try:
            _remove_dsh_patch(patch, mjs)
        except ValueError as exc:
            print(
                "cannot uninstall: %s: %s. The file may be a hand-written YAML "
                "patch; it was left unchanged. Remove the actx insert "
                "operation (the item inserting id \"actx\" with name "
                "\"./actx/actx-dsh.mjs\") manually." % (patch, exc),
                file=sys.stderr,
            )
            return 1
        _remove_file(mjs)
        return 0
    if agent == "hermes":
        return _uninstall_hermes(abs_actx)
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
