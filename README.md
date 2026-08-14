# actx

**Context compression for AI-agent shell commands.**

`actx` is a small, dependency-free CLI that compresses the output of read-only shell commands before it reaches an AI agent — fewer tokens, shorter context windows, cheaper and more focused agent sessions.

```text
$ git status        →   $ actx git status
```

![Python 3.14](https://img.shields.io/badge/Python-3.14-3776AB)
![Stdlib only](https://img.shields.io/badge/dependencies-none-brightgreen)
![Tests](https://img.shields.io/badge/tests-115%20passed-brightgreen)

---

## Why

AI agents run `git status`, `git diff`, `grep`, `find`, `ls` and then read their full output. Most of that output is noise: progress bars, repeated lines, boilerplate. `actx` sits between the agent and the shell, rewrites read-only commands through itself, and returns a compact, structured summary — while keeping the original exit code and a recoverable raw copy.

## Demo

Raw `git status`:

```text
On branch main
Your branch is up to date with 'origin/main'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
	modified:   src/main.py
	modified:   src/utils.py
	modified:   src/models/user.py
```

`actx git status`:

```text
* main
M (3):
  src/main.py
  src/utils.py
  src/models/user.py
```

Raw `git diff` becomes a per-file summary with real change counters:

```text
src/main.py
+12 -3
  +def compress(...)
  +    ...
  -    ...
  ... (truncated, full in tee)
```

## Features

- **Read-only auto-rewrite** — only `git status/diff/log`, `ls`, `grep`, and safe `find` are rewritten automatically. Mutating commands are never auto-rewritten.
- **Exact exit codes** — the original command's exit code is preserved, including `git status` returning `128` outside a repo and `grep` returning `1` for no matches.
- **Lossless filenames** — `git status`, `ls`, and `find` compress the format, not the names.
- **Tee for raw recovery** — truncated or failed output is saved to `~/.local/share/actx/tee` as JSON; `git diff` always saves, because its compression is lossy.
- **Fail-open everywhere** — hooks, adapters, and filters never throw into the agent; on any error they pass the command or output through unchanged.
- **Stdlib only** — Python 3.14 standard library. No pip, no brew, no network, no telemetry.
- **Multi-agent** — deterministic hooks for Claude Code, Codex, and OpenCode; rule-based instructions for Grok, Cline, Windsurf, Aider, and Cursor.

## Installation

Requirements: **Python 3.14** (macOS or Linux). No third-party packages.

```bash
chmod +x actx
# Put `actx` on PATH, e.g. symlink into a bin directory:
ln -s "$(pwd)/actx" ~/.local/bin/actx
```

Then install the adapters for the agents you use:

```bash
actx init              # auto-detect installed agents
actx init --agent all  # install for every supported agent
actx init --agent claude
actx init --agent codex
actx init --agent opencode
```

After installation, restart the agent.

## Usage

```text
actx [--raw] [-v|-vv|-vvv] <command> [args...]
actx run <cmd...>
actx rewrite "<command>"
actx hook
actx init [--agent <name>] [--show] [--uninstall]
actx --version
actx --help
```

| Command | Behavior |
|---|---|
| `actx git status` | Compact grouped status: `* branch`, `M (n):`, `?? (n):` |
| `actx git diff [args]` | Per-file `+A -B` counters and first changed lines; tee always |
| `actx git log [args]` | `git log --oneline` output |
| `actx ls [path]` | Directories first, then files, grouped by path |
| `actx grep [args] <pattern> [path...]` | Groups matches by file, truncates long lines |
| `actx find [args]` | Groups paths by directory |
| `actx read <file> [--level minimal]` | Strips full-line comments for known extensions |
| `actx run <cmd...>` | Generic wrapper: truncate lines/chars, tee on failure |
| `actx git add/commit/push/pull/branch` | Manual mutating commands; success prints a tiny confirmation |
| `actx --raw <command>` | Bypass filtering, print output verbatim |

Everywhere, `-v`/`-vv`/`-vvv` (before the subcommand) control debug output to stderr.

### Examples

```bash
actx git status
actx git diff --stat       # passthrough: --stat already compacts
actx ls src
actx grep "TODO" src/
actx find . -name "*.py"
actx read main.py --level minimal
actx run pytest tests/
actx --raw git status      # full original output
```

## How it works

```
agent Bash call
      │
      ▼
agent adapter (hook / plugin / rules)
      │
      ▼
actx rewrite "<command>"   →  "actx <command>" or nothing
      │
      ▼
actx CLI: parse → route → execute (exec-array) → filter → print → tee
      │
      ▼
compact output + original exit code
```

One rewriter is the single source of truth for every adapter. It only rewrites simple, read-only commands and returns the original command string verbatim with an `actx ` prefix — never rebuilt from tokens.

## Agent integration

| Agent | Mechanism | Install | Auto-rewrite |
|---|---|---|---|
| Claude Code | PreToolUse JSON hook | `actx init --agent claude` | ✅ deterministic |
| Codex | PreToolUse JSON hook | `actx init --agent codex` | ✅ deterministic¹ |
| OpenCode | TypeScript plugin | `actx init --agent opencode` | ✅ deterministic |
| Grok Build | Rules instruction | `actx init --agent grok` | soft (~70–85%) |
| Cline / Roo | Rules file | `actx init --agent cline` | soft |
| Windsurf | Rules file | `actx init --agent windsurf` | soft |
| Aider | `read:` instruction | `actx init --agent aider` | soft |
| Cursor | Printed for manual UI insert | `actx init --agent cursor` | manual |

¹ Codex requires the user to trust the hook once via `/hooks`.

`actx init` merges — it never overwrites your configuration files. `actx init --show` lists status, and `actx init --uninstall` removes only the actx entry.

## Configuration

Created automatically on first run at `~/.config/actx/config.json`:

```json
{
  "tee": {
    "enabled": true,
    "mode": "failures",
    "dir": "~/.local/share/actx/tee"
  },
  "truncate": {
    "max_lines": 500,
    "max_line_chars": 300
  }
}
```

- `tee.mode`: `failures` (default), `always`, or `never`.
- `git diff` always tees regardless of `mode`, because its compression is lossy.
- Tee files are `~/.local/share/actx/tee/<unix_ts>_<sha1(command)[:8]>.log`, kept to 100 files.

## Safety

- No `shell=True`, `os.system`, `eval`, or `exec` anywhere — every subprocess is an exec-array.
- Only read-only commands are auto-rewritten; the rewriter rejects shell metacharacters, pipes, redirects, and command substitution.
- No project configs are read; adapters write only to global user files.
- No network calls, accounts, or telemetry.

## Development

Run the full test suite (stdlib `unittest` only):

```bash
python3 -m unittest discover tests
```

The suite covers the rewriter security boundary, hook E2E, all filters, adapter installation, an AST security scan, and performance targets.

## Non-goals for v1

- Test-runner filters (pytest/cargo/go), linters, docker/kubectl
- `actx gain` / SQLite statistics
- Windows
- Mutating-command auto-rewrite

## License

Not yet chosen.
