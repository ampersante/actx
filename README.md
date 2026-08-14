# actx

**Context compression for AI-agent shell commands.**

`actx` is a small, dependency-free CLI that compresses the output of read-only shell commands before it reaches an AI agent — fewer tokens, shorter context windows, cheaper and more focused agent sessions.

```text
$ git status        →   $ actx git status
```

![Python 3.14](https://img.shields.io/badge/Python-3.14-3776AB)
![Stdlib only](https://img.shields.io/badge/dependencies-none-brightgreen)
![Tests](https://img.shields.io/badge/tests-129%20passed-brightgreen)

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
- **Escape hatch** — `ACTX_BYPASS=1` or a `bypass_commands` entry runs the matching command unfiltered (raw), preserving the exit code.
- **Stdlib only** — Python 3.14 standard library. No pip, no brew, no network, no telemetry.
- **Multi-agent** — deterministic hooks for Claude Code, Codex, and OpenCode; rule-based instructions for Grok, Cline, Windsurf, Aider, and Cursor.

## Installation

Requirements: **Python 3.14** (macOS or Linux). No third-party packages.

### From source

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

### Via curl (release tarball)

```bash
curl -fsSL https://github.com/ampersante/actx/archive/refs/tags/v2.2.tar.gz | tar xz
cd actx-2.2
bash install.sh
```

Keep the extracted directory — `install.sh` symlinks the `actx` binary from it.

### Via Homebrew

```bash
brew tap ampersante/actx
brew trust ampersante/actx
brew install actx
```

`brew` installs Python 3.14 automatically via the formula dependency.

## Uninstall

Step 1 first — while `actx` is still installed at the same path:

```bash
actx init --agent all --uninstall
actx init --show    # every agent except Cursor should read "not installed"
```

Cursor always shows `manual (cursor)` — that is fine, it was never written to
disk. You will also see a Cursor "nothing to uninstall" line on stderr; that is
expected. If you pasted the section into Cursor UI, remove it there by hand.
Restart the agent(s) before the next step.

Then remove the program:

```bash
rm ~/.local/bin/actx    # symlink install
brew uninstall actx     # instead, if you installed via Homebrew
```

If you installed by adding the `actx` directory to PATH, remove that line from
your shell config instead. If you installed via curl, also delete the extracted
directory.

Then remove user data (these are actx's own directories):

```bash
rm -rf ~/.config/actx ~/.local/share/actx
```

If you cloned `actx`, delete that folder too.

If you moved `actx` after installing, move it back to its original path, run
Step 1, then delete it; otherwise remove the old hooks from the agent config by
hand.

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
| `ACTX_BYPASS=1 actx <command>` | Run the command raw (no filter, no tee) |

`ACTX_BYPASS=1` disables filtering for that call; adding a command's first token to `bypass_commands` in the config does the same for every call of that command. Everywhere, `-v`/`-vv`/`-vvv` (before the subcommand) control debug output to stderr.

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
  },
  "bypass_commands": []
}
```

- `tee.mode`: `failures` (default), `always`, or `never`.
- `bypass_commands`: list of command names (first token) that run unfiltered, e.g. `["git"]`. Environment variable `ACTX_BYPASS=1` bypasses filtering for the current call only.
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

The suite covers the rewriter security boundary, hook E2E, all filters, adapter installation, an AST security scan, the bypass escape hatch, lazy-import guards, and performance targets.

## Non-goals for v1

- Test-runner filters (pytest/cargo/go), linters, docker/kubectl
- `actx gain` / SQLite statistics
- Windows
- Mutating-command auto-rewrite

## Releasing

1. Bump `VERSION` in `actx_lib/cli.py`, commit, and tag:

   ```bash
   git add actx_lib/cli.py
   git commit -m "Bump version to X.Y.Z"
   git tag vX.Y.Z
   git push origin master
   git push origin vX.Y.Z
   ```

2. Update the tap formula in the `homebrew-actx` repo: set the tag URL and the
   tarball sha256, then push the formula.

3. Update installed copies:

   ```bash
   brew update
   brew upgrade actx
   ```

`brew update` takes no arguments — `brew update <tap>` does not refresh a
single tap in current Homebrew.

## License

MIT. See `LICENSE`.
