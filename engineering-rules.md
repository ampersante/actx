# Engineering Rules — actx

Pre-dev: hard rules now; stack-specific idioms marked "refine with code".

## Principles (domain implementation invariants)

1. **One rewriter.** All command→rewritten logic lives in `actx_lib/rewriter.py`; adapters never contain rewrite logic. Source: `PRD.md` §7.
2. **Fail-open everywhere.** Hook, plugin, and filters must never raise to the caller on any input; on error, leave the command/output unchanged. Source: `PRD.md` §10.8, §6.1, §6.2.
3. **Exec-array only.** `subprocess.run([...], capture_output=True, text=True)`; never `shell=True`. Source: `PRD.md` §11.1–11.2.
4. **Exit code passthrough.** Return the original command's exit code exactly; actx internal errors use exit 1. Source: `PRD.md` §10.2, §5.
5. **Filter exceptions → raw passthrough.** Any filter error prints raw stdout+stderr and keeps the exit code. Source: `PRD.md` §8 common rules.
6. **No project configs.** Only `~/.config/actx/config.json`; all paths via `os.path.expanduser` with `$HOME`. Source: `PRD.md` §9, §11.5.
7. **`actx init` merges, never overwrites whole files.** JSON merge; Tier-2 instruction section appends, or replaces in place when the body differs (keyed by `## Output compression (actx)`). Dedupe hooks by exact `command` string. Source: `PRD.md` §6.4.

## General Practices

- **Errors**: distinguish expected (validation, no permission — handle and report) from bugs (fail loud). Messages carry what/where/what-to-do.
- **Secrets/config**: no secrets in v1 (no network/accounts). Never log full command strings; tee filenames hash the command (`sha1`). Source: `PRD.md` §11.6.
- **Dependencies**: stdlib first, always — no pip/brew installs. A third-party dependency is out of scope by `PRD.md` §3.
- **Security**: validate all external input at the boundary — hook stdin must tolerate invalid JSON / missing keys without raising. Source: `PRD.md` §6.1.
- **Version control**: no git repo yet; from the first commit — atomic commits, minimal diffs, no secrets/artifacts.

## Efficiency (work fast without cutting corners)

- **KISS**: the simplest thing satisfying the spec wins; extra structure is a defect.
- **Rule of three**: no abstraction before a third real use; YAGNI.
- **Reuse before writing**: search existing modules; follow existing patterns.
- **Minimal diffs**: solve the task with the smallest change; no side-refactors.
- **No premature optimization**: perf targets (`PRD.md` §12) are measured last (§13.10); optimize after a profile, not before.
- **Fast feedback**: `python3 -m unittest discover tests` as the tight loop.

## Python Conventions (refine with code)

- stdlib only: argparse, subprocess, shlex, json, os, sys.
- `actx hook` / `actx rewrite` import only json/sys/shlex (+ rewriter); filters are imported lazily by subcommand. Source: `PRD.md` §4.
- Parse with `shlex.split`; never rebuild commands from tokens — return the original string verbatim (`"actx " + command`). Source: `PRD.md` §7.
- Tests: `unittest` (not pytest); fixture-based, deterministic.

## TypeScript Adapter (OpenCode)

- One file `adapters/opencode.ts.template`; installer substitutes `__ACTX_ABS_PATH__` via `json.dumps` (a valid TS string literal).
- No rewrite logic in TS; delegate to `actx rewrite`. Fail-open try/catch leaves the command unchanged. Source: `PRD.md` §6.2.

## Naming

- Modules per `PRD.md` §4: `actx_lib/<name>.py`; filters `actx_lib/filters/<name>_filter.py`; tests `tests/test_<module>.py`; snake_case.

## Tests (what to cover first)

1. Rewriter (`PRD.md` §13.3) — the security boundary; cover all reject cases.
2. Hook E2E (§13.4).
3. Filters with fixtures (§13.5, §13.8).
4. Init idempotence/merge (§13.9).
5. AST security test (§13.2) — mechanical ban on `eval`/`exec`/`os.system`/`subprocess(..., shell=True)`.
6. Perf (§13.10) last, with 3× tolerance.

## What NOT to do

- No `shell=True`, `os.system`, `os.popen`, `eval`, `exec`.
- No pytest/toml/rich/click/typer; no pip/brew installs.
- No auto-rewrite outside the §7 allow-list (no `python3`/`aws`, no lexer/compounds); no rewrite logic in adapters.
- No project configs; no overwriting user config files wholly.
- No network calls; no telemetry.
