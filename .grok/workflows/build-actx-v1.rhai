let meta = #{
    name: "build-actx-v1",
    description: "Implement actx v1 from PRD.md: scaffold + rewriter, CLI/runner/config, filters, JSON hook, installer, acceptance, verification, tracker close.",
    phases: [
        #{ title: "Scaffold", detail: "TK-01 skeleton + rewriter" },
        #{ title: "Core", detail: "TK-02 CLI, runner, config" },
        #{ title: "Filters", detail: "TK-03 git/system/read filters" },
        #{ title: "Hook", detail: "TK-04 JSON hook" },
        #{ title: "Installer", detail: "TK-05 adapters" },
        #{ title: "Acceptance", detail: "TK-06 security + perf" },
        #{ title: "Verify", detail: "independent full-suite check" },
        #{ title: "Record", detail: "close tasks + handoff" },
    ],
};

let task_schema = #{
    "type": "object",
    "required": ["ok", "summary"],
    "properties": #{
        "ok": #{ "type": "boolean" },
        "summary": #{ "type": "string" },
        "tests": #{ "type": "string" },
    },
};

let verdict_schema = #{
    "type": "object",
    "required": ["ok", "summary", "evidence"],
    "properties": #{
        "ok": #{ "type": "boolean" },
        "summary": #{ "type": "string" },
        "evidence": #{ "type": "string" },
    },
};

let ctx = "This is actx, a personal CLI context-compressor for AI agents. Workspace root is the current working directory. Product source of truth: PRD.md; task tracker: tasks.md; engineering rules: engineering-rules.md; target architecture: architecture.md. Read the relevant PRD sections and your tasks.md entry BEFORE writing code.\n";
ctx += "Hard invariants you must obey: (1) Python 3.14.2 stdlib only - unittest, argparse, subprocess, shlex, json, os, sys; no pip/brew, no pytest/toml/rich/click/typer. (2) NEVER use shell=True, os.system, os.popen, eval, or exec; every subprocess is an exec-array with capture_output=True, text=True. (3) actx_lib/rewriter.py is the single source of truth for command rewriting; adapters never contain rewrite logic. (4) All adapters, hooks, and filters fail open: never raise to the caller on any input; on error leave the command or output unchanged. (5) Preserve the original command exit code exactly; actx internal errors exit 1. (6) No project configs; all paths resolve via os.path.expanduser with $HOME.\n";

fn run_task(label, prompt, schema) {
    let r = agent(prompt, #{ label: label, capability_mode: "all", output_schema: schema });
    if r != () && r.success && type_of(r.output) == "map" && r.output.ok == true {
        #{ ok: true, task: label, summary: r.output.summary }
    } else {
        let reason = "agent failed or returned no result";
        if r != () && type_of(r.output) == "string" { reason = r.output; }
        if r != () && type_of(r.output) == "map" && r.output.summary != () { reason = r.output.summary; }
        #{ ok: false, task: label, summary: reason }
    }
}

let results = [];

phase("Scaffold");
let p1 = ctx;
p1 += "TASK TK-01 (scaffold + rewriter). Create the project skeleton per PRD.md section 4 and implement the rewriter strictly per PRD.md section 7.\n";
p1 += "Files to create: executable `actx` (shebang #!/usr/bin/env python3, chmod +x), actx_lib/__init__.py, actx_lib/rewriter.py, actx_lib/filters/__init__.py (empty placeholder), adapters/ (empty directory), tests/test_rewriter.py.\n";
p1 += "Entrypoint `actx` must dispatch by argv[1] and implement the rewrite route exactly per PRD.md section 5: the rewrite subcommand takes exactly one argument argv[2] containing the full command string; prints `actx <command>` or nothing to stdout; exit always 0; missing argument -> empty stdout exit 0; extra argv[3] -> message on stderr and exit 1. The rewrite path must import only sys and actx_lib.rewriter (rewriter imports shlex). Any other argv[1] -> print not implemented to stderr and exit 1.\n";
p1 += "rewriter.py implements rewrite(command) -> `actx ` + command verbatim or None, exactly per PRD.md section 7 (empty command, idempotent actx prefix, length over 4096, forbidden metacharacters, shlex.split failure, dispatch table for git/ls/grep/find, return the original string verbatim - never rebuild from tokens).\n";
p1 += "tests/test_rewriter.py must cover every case in PRD.md section 13.3, including invoking the `actx` script for the extra-argument case. DoD: run `python3 -m unittest discover tests` from the workspace root; it must pass. Do not create files outside this list. Report ok=true only after the tests actually pass; include the tail of the test output in the `tests` field.";
let t1 = run_task("TK-01", p1, task_schema);
if t1.ok {
    results.push(#{ task: t1.task, status: "ok", summary: t1.summary });
} else {
    complete(#{ status: "failed", phase: "Scaffold", reason: t1.summary, tasks: results });
}

phase("Core");
let p2 = ctx;
p2 += "TASK TK-02 (CLI, runner, config). Implement actx_lib/cli.py, actx_lib/runner.py, actx_lib/config.py and replace the `actx` entrypoint to dispatch through cli.main().\n";
p2 += "Read PRD.md sections 5, 8.8, 9 and your tasks.md TK-02 entry.\n";
p2 += "cli.py: argparse dispatcher; global flags --raw and -v/-vv/-vvv are recognized ONLY before the subcommand; --version and --help work; filters are imported lazily. Implement the rewrite subcommand by delegating to actx_lib.rewriter and keep the exact contract from TK-01 (exactly one argument; extra argv[3] -> exit 1). Implement `actx run <cmd...>` via runner. Add lazy-import routes for `hook` (import actx_lib.hook) and `init` (import actx_lib.installer) inside their branches; those modules do not exist yet and that is expected - do not create them.\n";
p2 += "For the git/ls/grep/find/read subcommands in this task, add a temporary generic passthrough: execute the raw command through an exec-array and print stdout/stderr unfiltered, preserving the exit code. (TK-03 will replace these with real filters.) This is required so `actx git status` in a non-git directory exits 128.\n";
p2 += "runner.py: per PRD.md section 8.8 (exec-array, truncate to truncate.max_lines and truncate.max_line_chars, tee policy auto, preserve exit code exactly). config.py: per PRD.md section 9 (load/save JSON config with defaults, create ~/.config/actx/config.json on first run, paths via os.path.expanduser with $HOME).\n";
p2 += "Add tests (for example tests/test_runner.py and tests/test_config.py) for: `actx run false` creates a tee file whose JSON has exit_code 1; `actx git status` outside a git repo exits 128; config is created with defaults. DoD: `python3 -m unittest discover tests` green; existing test_rewriter.py must still pass. Do not create actx_lib/hook.py, actx_lib/installer.py, or any filter modules. Report ok=true only after the tests pass; include the tail of the test output in the `tests` field.";
let t2 = run_task("TK-02", p2, task_schema);
if t2.ok {
    results.push(#{ task: t2.task, status: "ok", summary: t2.summary });
} else {
    complete(#{ status: "failed", phase: "Core", reason: t2.summary, tasks: results });
}

phase("Filters");
let p3 = ctx;
p3 += "TASK TK-03 (filters). Implement the compression filters per PRD.md sections 8.1 through 8.9 and wire them into the CLI dispatch, replacing the temporary passthrough from TK-02 for git/ls/grep/find/read.\n";
p3 += "Files: actx_lib/filters/git_filter.py, actx_lib/filters/system_filter.py (ls, grep, find), actx_lib/filters/read_filter.py; update actx_lib/filters/__init__.py with REGISTRY name -> filter; update actx_lib/cli.py to route git status/diff/log, ls, grep, find, read to the filters via lazy imports; add tests test_git_filter.py, test_system_filter.py, test_read_filter.py.\n";
p3 += "Follow PRD.md section 8 common rules exactly: passthrough semantics, exec-array only, exit-code handling (grep exit 1 means no matches), tee_policy auto for all filters and always for git diff, and filter exception -> raw passthrough. Read every subsection 8.1 through 8.9 before coding; the passthrough trigger lists are exact - do not guess them.\n";
p3 += "DoD: run `python3 -m unittest discover tests`; the whole suite must pass, including existing tests and your new filter tests covering PRD.md sections 13.5, 13.7, 13.8. Report ok=true only after the full suite passes; include the tail of the test output in the `tests` field.";
let t3 = run_task("TK-03", p3, task_schema);
if t3.ok {
    results.push(#{ task: t3.task, status: "ok", summary: t3.summary });
} else {
    complete(#{ status: "failed", phase: "Filters", reason: t3.summary, tasks: results });
}

phase("Hook");
let p4 = ctx;
p4 += "TASK TK-04 (JSON hook). Implement actx_lib/hook.py per PRD.md section 6.1 and make the `actx hook` route work through the existing cli.py lazy import.\n";
p4 += "hook.py reads a JSON PreToolUse input from stdin and writes JSON to stdout, or writes nothing on no-op (exit 0). Input is untrusted: invalid JSON, missing tool_name, tool_name not in {Bash, bash, Shell}, tool_input not a dict, or command missing/not a string -> no-op (exit 0, empty stdout) with no exception. On rewrite, output exactly the hookSpecificOutput object from PRD.md section 6.1 with permissionDecision allow, updatedInput copying ALL original tool_input keys and replacing command, and the additionalContext string. Diagnostics go to stderr only.\n";
p4 += "Do not modify rewriter.py - call actx_lib.rewriter.rewrite(). Add tests/test_hook.py covering every case in PRD.md section 13.4. DoD: `python3 -m unittest discover tests` green. Report ok=true only after the suite passes; include the tail of the test output in the `tests` field.";
let t4 = run_task("TK-04", p4, task_schema);
if t4.ok {
    results.push(#{ task: t4.task, status: "ok", summary: t4.summary });
} else {
    complete(#{ status: "failed", phase: "Hook", reason: t4.summary, tasks: results });
}

phase("Installer");
let p5 = ctx;
p5 += "TASK TK-05 (installer + adapters). Implement actx_lib/installer.py per PRD.md section 6.4 and adapters/opencode.ts.template per PRD.md section 6.2; make the `actx init`, `--show`, and `--uninstall` routes work through the existing cli.py lazy import.\n";
p5 += "Installer supports --agent {claude, codex, opencode, grok, cursor, cline, windsurf, aider, all} and auto-detection (default, no --agent). Rules: NEVER overwrite existing files wholesale; merge JSON hooks / append the Tier-2 instruction section; dedupe by exact command string or the `## Output compression (actx)` header; all paths via os.path.expanduser with $HOME so tests can override HOME. abs_path = os.path.realpath(sys.argv[0]). Follow the per-agent algorithm and uninstall cleanup from PRD.md section 6.4 exactly; cursor only prints the section to stdout; aider edits the read: key in YAML.\n";
p5 += "Create adapters/opencode.ts.template with the placeholder __ACTX_ABS_PATH__ exactly as in PRD.md section 6.2; the installer substitutes it with json.dumps(abs_path).\n";
p5 += "Add tests/test_init.py covering PRD.md section 13.9 for every agent (double init -> one entry, --show, --uninstall removes only actx, claude non-JSON settings.json -> exit 1 without changing the file, opencode template checks, Tier-2 section verbatim, aider scalar and list forms, cursor writes nothing). DoD: `python3 -m unittest discover tests` green. Report ok=true only after the suite passes; include the tail of the test output in the `tests` field.";
let t5 = run_task("TK-05", p5, task_schema);
if t5.ok {
    results.push(#{ task: t5.task, status: "ok", summary: t5.summary });
} else {
    complete(#{ status: "failed", phase: "Installer", reason: t5.summary, tasks: results });
}

phase("Acceptance");
let p6 = ctx;
p6 += "TASK TK-06 (acceptance + performance). Add the remaining acceptance tests and run the full suite, fixing any failures within scope.\n";
p6 += "Add tests/test_security.py implementing the AST security test from PRD.md section 13.2: parse actx_lib/ and the root `actx` script with ast, walk Call/Name/keyword nodes, and assert absence of eval, exec, os.system, os.popen, and subprocess.run/Popen/call/check_call/check_output/getoutput/getstatusoutput with shell=True (or shell=1). The test must pin the concrete symbols it checks and must actually catch a substituted violation.\n";
p6 += "Add or complete tests/test_integration.py for any remaining executable acceptance criteria in PRD.md section 13 that are not yet covered, and add tests/test_perf.py for PRD.md section 13.10 (warm-up run then median of 5, 3x tolerance): `actx hook` and `actx rewrite` under 30 ms, `actx git status` overhead at most 40 ms, 10 MB output filtering at most 2 s.\n";
p6 += "Do NOT change the rewriter whitelist, the adapters mechanism, or any invariant in PRD.md without good reason; if you find a real bug, fix it minimally and note it in your summary. DoD: `python3 -m unittest discover tests` entirely green. Report ok=true only after the full suite passes; include the tail of the test output in the `tests` field.";
let t6 = run_task("TK-06", p6, task_schema);
if t6.ok {
    results.push(#{ task: t6.task, status: "ok", summary: t6.summary });
} else {
    complete(#{ status: "failed", phase: "Acceptance", reason: t6.summary, tasks: results });
}

phase("Verify");
let p7 = "Independent verification. Do NOT modify any files. From the workspace root run `python3 -m unittest discover tests` and confirm every test passes; paste the last 20 or so lines of the output as evidence.\n";
p7 += "Then verify these invariants by reading and grepping the code (do not rely on tests alone): (1) no shell=True, os.system, os.popen, eval, exec anywhere; (2) actx_lib/rewriter.py is the only module with command-rewriting logic and matches PRD.md section 7; (3) no project configs are read and adapters write only to global user files (cursor prints only); (4) hooks, filters, and adapters fail open.\n";
p7 += "If the suite passes and the invariants hold, ok=true with evidence. If anything fails, ok=false with the concrete evidence.";
let r7 = agent(p7, #{ label: "verify-full-suite", capability_mode: "all", output_schema: verdict_schema });
let verify_ok = false;
let verify_evidence = "verifier returned no result";
if r7 != () && r7.success && type_of(r7.output) == "map" && r7.output.ok == true {
    verify_ok = true;
    verify_evidence = r7.output.evidence;
} else {
    if r7 != () && type_of(r7.output) == "string" { verify_evidence = r7.output; }
    if r7 != () && type_of(r7.output) == "map" && r7.output.summary != () { verify_evidence = r7.output.summary; }
}

let report = "# actx v1 build report\n\n";
for t in results {
    report += "## " + t.task + ": " + t.status + "\n" + t.summary + "\n\n";
}
report += "## Verification\n";
if verify_ok {
    report += "PASS\n" + verify_evidence + "\n";
} else {
    report += "FAIL\n" + verify_evidence + "\n";
}

if verify_ok {
    phase("Record");
    let p8 = "Bookkeeping. The build succeeded and verification passed. Update the project tracker files (they are in Russian; keep them Russian) without touching code.\n";
    p8 += "Read tasks.md. Move each of the six closed tasks TK-01 through TK-06 from the active section to a closed section in Архив/tasks-done.md (create the file if missing), preserving the task format documented in tasks.md. Remove them from the active section of tasks.md. Then update session-handoff.md: status = code implemented, unittest suite green; next steps = manual install steps from PRD.md section 16 (chmod +x, PATH, actx init, Codex /hooks trust, Cursor UI rules, OpenCode manual check section 13.11) and the v2 backlog.\n";
    p8 += "Do not modify any source files. Report ok=true after making the tracker updates; include a one-line summary of what changed.";
    let r8 = agent(p8, #{ label: "record-close-tasks", capability_mode: "all", output_schema: task_schema });
    report += "## Tracker\n";
    if r8 != () && r8.success && type_of(r8.output) == "map" && r8.output.ok == true {
        report += r8.output.summary + "\n";
    } else {
        report += "update failed: ";
        if r8 != () && type_of(r8.output) == "string" { report += r8.output; }
        else if r8 != () && type_of(r8.output) == "map" && r8.output.summary != () { report += r8.output.summary; }
        else { report += "no result"; }
    }
    let p = write_scratch_file("report.md", report);
    complete(#{ status: "success", path: p, report: report, tasks: results });
} else {
    let p = write_scratch_file("report.md", report);
    complete(#{ status: "verification-failed", path: p, report: report, tasks: results });
}
