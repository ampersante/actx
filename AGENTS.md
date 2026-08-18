# actx — personal CLI context-compressor for AI agents (pre-dev)

## Routing
Each file owns one layer; here are pointers only.

**On start (every session, minimal):**
- `@session-handoff.md` — where we stopped. Read first.
- `@architecture.md` — system snapshot (target, code not started).

**On demand (under task) — plain links with a trigger, no `@`:**
- Before a structural/architecture decision — `journal.md`.
- Before changing a dependency, runtime/version, data schema, or provider — `assumptions.md`.
- Product/scope — `PRD.md` (single product source of truth).
- To pick up work — `tasks.md`; read one entry only: `awk '/^### TK-/{f=1;print;next} f&&/^### /{exit} f' tasks.md`.
- Before writing code — `engineering-rules.md`.

## Project Invariants
Rules, not fact copies; each points to its owner (PRD).

- **Python stdlib-only core.** Python 3.14.2; no pip/brew installs; unittest, JSON, argparse only. Source: `PRD.md` §3.
- **No `shell=True` / `os.system` / `eval` / `exec` anywhere.** Every subprocess is an exec-array. Source: `PRD.md` §11.1–11.2.
- **Auto-rewrite observational CLI + narrow mutator allow-list.** Observational heads (git RO, ls/grep/find/wc/…, test runners, linters without write flags, docker/kubectl/gh RO, …) plus mutators: `git add|commit|push|pull|fetch`, `npm|pnpm install|ci`, `pip install`, `uv pip install`. Safety = metachar/exec/fail-open/write-flag rejects, not list length. No lexer; no `python3`/`aws` auto-rewrite. Source: `PRD.md` §7.
- **One rewriter for all agents.** `actx_lib/rewriter.py` is the single source of truth; adapters are transport only. Source: `PRD.md` §4, §7.
- **Adapters fail open.** Hook and plugin never throw on any input; `actx init` merges, never overwrites user files wholly. Source: `PRD.md` §10.7–10.8, §6.4.
- **No project configs; adapters write only to global user files.** Source: `PRD.md` §2, §11.5.
- **Original exit code preserved exactly.** Source: `PRD.md` §10.2.
- **No network, telemetry, or accounts.** Source: `PRD.md` §2.

## Build & Run
Pre-dev: no code, no git repo yet. When implemented:
- Tests: `python3 -m unittest discover tests` (stdlib only). Source: `PRD.md` §13.1.

## Coding Standards
See `engineering-rules.md` before writing code.

## Language
Per-file language (user decision, 2026-08-14):
- English: `AGENTS.md`, `CLAUDE.md`, `architecture.md`, `engineering-rules.md`.
- Russian: `tasks.md`, `journal.md`, `assumptions.md`, `meta-journal.md`, `session-handoff.md`, `PRD.md`.
One language per file; technical terms stay English.

---
## Operating Rules for the Engineer

**Role.** Implement the PRD faithfully. The implementing agent may not have this conversation, so `PRD.md` is self-sufficient (`PRD.md` §3.5).

**Output style.** Dense and concrete; a task is done only with observable evidence of its DoD.

### Always
- Read `@session-handoff.md` first, then `@architecture.md`.
- Before touching architecture, the rewriter whitelist, an adapter mechanism, or dependencies — read `journal.md` + `assumptions.md`.
- Never break an invariant above without a `journal.md` entry and user sign-off.
- No new dependencies; stdlib only. No local Node/npm.

### Before writing code
- Read `engineering-rules.md` and the relevant `tasks.md` entry.

### Execution
- No git repo yet; from the first commit — atomic commits, minimal diffs.
- Run `python3 -m unittest discover tests` before declaring a task done.
- Verify claims with tool output; do not record an agent/memory claim as fact unverified.

### Journal rules
- Append-only, causal entries; the record format is shown in `journal.md`.

### Working files format
- `tasks.md`: `### TK-NN` + `Статус`/`Постановка`/`DoD`/`Соседи`. A closed task moves to `Архив/tasks-done.md` immediately.
- No duplication of working state between `tasks.md` and `session-handoff.md`.

### When blocked
- Product fork → ask the user, don't guess. Tech uncertainty → research current sources (≤6 months) and propose a senior-defensible choice.
