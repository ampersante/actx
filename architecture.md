# Architecture — actx

Living snapshot (v2.9.0). Product source of truth: `PRD.md`.

## System Overview

Agent-agnostic core; per-agent thin adapters for transport only.

```
┌────────────────────────────────────────────────────────────┐
│  actx_lib/rewriter.py   command → rewritten | None          │
│  actx_lib/filters/*.py  compression engine (agent-agnostic) │
└─────────────────────────────┬──────────────────────────────┘
                              │
      ┌───────────────────────┼────────────────────────────┐
      ▼                       ▼                            ▼
 actx hook (JSON)      actx rewrite "<cmd>" (CLI)    actx init --agent X
 for Claude/Codex/     for OpenCode plugin           (writes adapter X)
 Gemini/Copilot
```

Data flow (hook/plugin agents):

```
agent Bash call → adapter → actx (rewrite) → agent executes
"actx <cmd>" → actx CLI → parse → route → execute (subprocess, exec-array,
no shell) → filter → print compact / tee → original exit code
```

Six-phase lifecycle (borrowed from RTK): parse → route → execute → filter → print → track.

Rewriter (post-wave-2): observational CLI + narrow mutator allow-list (`PRD.md` §7); metachar/write-flag rejects (SQL heads psql/sqlite3/duckdb get the quote-aware guard instead of the raw metachar reject); no lexer; no `python3`/`aws` auto-rewrite; install-class verbs (npm/pip/uv) left the allow-list (TK-51 always-ask policy — installs escalate to T5-ask on the hook path).

## Components

| Layer | Tech | Role |
|---|---|---|
| `actx` | Python 3.14.2, stdlib | entrypoint; dispatch by `argv[1]` |
| `actx_lib/security_gate.py` | stdlib (json/shlex/re) | L7 Security Gatekeeper: deterministic prompt-injection / secret access / exfiltration defense (<1ms) |
| `actx_lib/cli_families.py` | stdlib (pure data) | declarative CLI family table (13 heads: 7 cloud + docker/kubectl/helm/bq/terraform/redis-cli; ro_verbs/ask_specs/stream_specs + global_flags/value_flags + `effective_verbs` skip-logic); single data source for rewriter `_DISPATCH`, `T6_ASK_TABLE` and hang-policy stream specs |
| `actx_lib/conventions.py` | stdlib (shlex in hint_for) | compact-flag conventions table (TK-45): single data source for the Tier-2 instruction block, hook `additionalContext` hints (allow+rewrite verdicts only) and insights suggestions; `WAVE_HEADS` frozenset feeds the TK-46 adoption metric |
| `actx_lib/sql_verbs.py` | stdlib (re) | SQL payload classification data (TK-43): RO-verb class, worst-verb regex, psql/dot meta blacklist, default-deny; shared by rewriter predicates and the security gate |
| `actx_lib/rewriter.py` | stdlib (json/sys/shlex) | single source of truth: command → rewritten; quote-aware guard for SQL heads (psql/sqlite3/duckdb — §7.4 exception) |
| `actx_lib/cli.py` | argparse | CLI dispatch; lazy filter imports |
| `actx_lib/runner.py` | stdlib | execute, exit-code, tee; TK-47 advisory stderr hints (auth/rate-limit, single emission per terminal path, synthetic 124/125 results excluded) |
| `actx_lib/hook.py` | stdlib | JSON PreToolUse hook (Claude/Codex/Gemini/Copilot): security evaluation + rewrite |
| `actx_lib/rewrite_cmd.py` | stdlib | `actx rewrite "<cmd>"` |
| `actx_lib/installer.py` | stdlib | `actx init/--show/--uninstall` |
| `actx_lib/config.py` | stdlib | JSON config load/save |
| `actx_lib/filters/` | stdlib | git_filter, system_filter (ls/grep/find), read_filter; compact_profiles (declarative test-runner/linter compaction profiles + engine, golden-dump byte contract), ascii_table_filter (framed-table → CSV-like, raw fallback), json_compactor; infra_filter (docker/kubectl/helm/gh/aws), mobile_filter (flutter/dart/swift/swiftlint/swiftformat/xcodebuild/xcrun/pod/gradlew), data_filter (psql/sqlite3/duckdb SQL tables w/ column masking, terraform, redis, dbt) |
| `adapters/opencode.ts.template` | TS (OpenCode Bun runtime) | thin transport; delegates to `actx rewrite` |

## Key Flows

1. **Tier 1 hook (Claude/Codex/Gemini/Copilot)**: PreToolUse JSON hook → `actx hook` → `security_gate.evaluate_security()`:
   - On violation (T1..T5, T7) $\to$ structured `deny` with reason.
   - On high-risk mutation (T6) $\to$ structured `ask` (Claude/Codex) or `force_ask` (Gemini/Antigravity) for human confirmation.
   - On clean command $\to$ `rewriter.rewrite()`:
     - if eligible $\to$ `allow` with compressed `updatedInput`.
     - if not eligible $\to$ `None` (defer to native agent harness permissions).
     - on allow+rewrite, `additionalContext` carries the compact-flag hint for known verbose forms (`conventions.hint_for`, fail-open; deny/ask and the Antigravity schema stay hint-free).
2. **Tier 1 rewrite (OpenCode)**: TS plugin `tool.execute.before` mutates `output.args.command` via `execFileSync(ACTX, ["rewrite", cmd])`.
3. **Tier 2 (Grok/Cursor/Cline/Windsurf/Aider)**: instruction section in agent rules (`PRD.md` §6.3; replace-in-place on reinit when body differs); agent prefixes supported commands manually; adoption ~70–85% (estimate).
4. **CLI**: `actx <cmd>` executes, filters, prints compact output, tee on failure/always (git diff), preserves exit code.

## Data Model

- Config: `~/.config/actx/config.json` → `{"tee":{"enabled","mode","dir"},"truncate":{"max_lines","max_line_chars"},"timeouts":{"default_s","generous_s"},"bypass_commands":[],"custom_heads":[],"tracking":{"enabled":true,"history_days":90}}`; created with defaults on first run. `custom_heads`: `actx <head>` gets `actx run` semantics (never extends the §7 rewriter whitelist).
- Tracking: `~/.local/share/actx/history.db` stores `sha1(command)`, `category`, `strategy`, bytes before/after, exit code, timestamp.
- Tee file: `~/.local/share/actx/tee/<unix_ts>_<sha1(cmd)[:8]>.log`, JSON `{"command","stdout","stderr","exit_code"}`; retention 100 files / 10 MB per stream.

## Open Forks

None. PRD §15 resolved 2026-08-14: CLI name `actx`; tee dir `~/.local/share/actx/tee`.
v1 boundaries (not forks, out of scope): `PRD.md` §14.
