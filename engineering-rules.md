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
- **Script before model**: extraction, enumeration and comparison over machine-readable sources (`--help`, files, DBs, git, test corpora) are done by a script; an LLM judges only the residue the script cannot classify. LLM-produced data is unverified until a script checks it — never by another LLM review.
- **Stop when slow**: when work takes clearly longer than expected, stop and name the cause (mechanism, process or organisation) before continuing the same way.

## Security Surfaces

- **Allowlist, default deny**: any path where the default outcome is dangerous (auto-approval, access, execution) admits only what is explicitly listed; unknown input is refused. Never close a class by growing a denylist.
- **Change the mechanism, not the list**: two consecutive review rounds finding new members of the same defect class mean the mechanism is wrong — stop patching.
- **Boundary first**: before code, write the boundary in one sentence with 2–3 examples inside and outside; reviews check compliance with it, not re-open it. Current boundary: `PRD.md` §7 (only code inlined in argv is refused; file/directory/project selectors are allowed).
- **Stopping criterion first**: for adversarial work define "done" up front; after release, findings inside the boundary are bug reports, not blockers.
- **Rank by outcome**: executed without confirmation > asks for confirmation > denied. Lost convenience is not a hole.
- **Catch-all is safe**: a catch-all exception handler in security code returns the safe verdict; if the contract requires fail-open, a static check must prevent a bug from becoming a silent allow.

## Evidence

- **Reproduce before fixing**: every finding (own, reviewer, auditor, agent) is reproduced by a command first; not reproducible — not accepted.
- **Agent reports are claims**: "all green" from an executor is re-run by the parent before merge.
- **Perf claims need a paired run**: a regression is asserted only from a same-run comparison against the base version, with machine load recorded.
- **Version-scoped facts**: "flag/API does not exist" is stated with the tool version checked.
- **Check data provenance**: before using data as ground truth, check how it was recorded (e.g. `history.db` stores `" ".join` — quotes lost, not an exact corpus).

## Structure (part of every DoD)

- A new rule is a data row, not a code branch; one mechanism per class; no duplicated tables between modules; a replaced mechanism is deleted completely.
- No line budgets; bloat is judged qualitatively (duplication, dead code, needless abstraction).
- Comments change in the same commit as the behaviour they describe.

## Privacy

- Owner identifiers (paths, email, client names) never enter the repo in any form, not even as literals of a privacy check — pass them at runtime.
- Data derived from personal history/logs is never committed; fixtures are synthetic or test-derived.
- Before every push, scan all published commits for owner identifiers; if found before publishing, rewrite the unpushed history after creating a backup branch.

## Delegation and Parallel Work

- Independent tasks with disjoint files go to parallel executors, not one executor sequentially.
- Every file touched by more than one stream has one owner and a fixed merge order.
- Parallel git worktrees share one `stash` stack — never use `git stash`; set work aside with a patch file or WIP commit.
- An executor brief is self-contained: contract paths, owned files, red→fix→green order, environment gotchas, report format.
- Plan review depth matches risk and available mechanical checks: with equivalence checks in place, one external review of the mechanism is enough.
- Owner decisions are asked in terms of the owner's criteria (safety, autonomy, data completeness), not technical options; when the criteria already decide it, decide and explain.

## Python Conventions (refine with code)

- stdlib only: argparse, subprocess, shlex, json, os, sys.
- `actx hook` / `actx rewrite` import only json/sys/shlex (+ rewriter); filters are imported lazily by subcommand. Source: `PRD.md` §4.
- Parse with `shlex.split`; never rebuild commands from tokens — return the original string verbatim (`"actx " + command`). Source: `PRD.md` §7.
- Tests: `unittest` (not pytest); fixture-based, deterministic.

## TypeScript Adapters (OpenCode, pi)

- One file per agent: `adapters/opencode.ts.template`, `adapters/pi.ts.template`; installer substitutes `__ACTX_ABS_PATH__` via `json.dumps` (a valid TS string literal).
- No rewrite or gate logic in TS: each adapter sends the Claude-format payload to `actx hook --agent <name>` (one actx process per command) and only applies the verdict. Policy differences between harnesses live in `actx_lib/hook.py` (`AGENT_POLICIES`), never in the template. Source: `PRD.md` §6.1, §6.2, §6.6.
- Fail-open: any actx failure (missing binary, timeout, non-JSON) leaves the command unchanged. OpenCode treats any thrown exception as a deny, so its only intentional throw is the gate's deny; pi blocks on a throwing handler, so the pi handler never throws and returns `{block: true, reason}` instead.
- pi awaits an async `spawn` (its event loop must not freeze); OpenCode uses synchronous `execFileSync` (argv, `timeout` and `stdio` live-verified under its Bun; stdin via `input:` was live-verified on 2026-10-01 — `assumptions.md` A1; `actx hook --payload` remains an unused fallback).
- No JS/TS runtime is available locally: templates are checked by string tests and live acceptance only (`PRD.md` §13.11).

## Naming

- Modules per `PRD.md` §4: `actx_lib/<name>.py`; filters `actx_lib/filters/<name>_filter.py`; tests `tests/test_<module>.py`; snake_case.

## Tests (what to cover first)

1. Rewriter (`PRD.md` §13.3) — the security boundary; cover all reject cases.
2. Hook E2E (§13.4).
3. Filters with fixtures (§13.5, §13.8).
4. Init idempotence/merge (§13.9).
5. AST security test (§13.2) — mechanical ban on `eval`/`exec`/`os.system`/`subprocess(..., shell=True)`.
6. Perf (§13.10) last, with 3× tolerance.

Rules for every test:
- Assert the exact outcome (category, value, output), never just "not X".
- Rules defined as data get tests generated from that data, per element; hand-picked samples are not coverage.
- Before changing behaviour, snapshot the old behaviour on a corpus and prove the new one does nothing the old did not; every behaviour loss is an owner decision (`tools/replay.py`).
- Before putting a behaviour change in a plan, grep the tests that pin the current behaviour.
- A "no behaviour change" refactor is proven mechanically: output equivalence on a corpus, AST identity of moved code, and a check that every name used is defined in its module (`tools/ast_identity_check.py`, `tests/test_gate_package_names.py`).
- Wall-clock limits flake under load: compare against the base in the same run or count calls.

## What NOT to do

- No `shell=True`, `os.system`, `os.popen`, `eval`, `exec`.
- No pytest/toml/rich/click/typer; no pip/brew installs.
- No auto-rewrite outside the §7 allow-list (no `python3`/`aws`, no lexer/compounds); no rewrite logic in adapters.
- No project configs; no overwriting user config files wholly.
- No network calls; no telemetry.
