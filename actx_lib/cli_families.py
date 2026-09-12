"""Declarative table of CLI families (TK-39; docker TK-41, kubectl/helm TK-40).

Pure data + pure functions (effective_verbs, run_prefix_split,
gradle_task_class), zero imports: rewriter, security_gate and hang_policy
all read it directly, so the cheap hook/rewrite
import boundary must not gain transitive modules. Connecting a new CLI family
is a data edit here, not a new predicate. Not only cloud CLIs live here:
docker joined in TK-41, kubectl/helm in TK-40 and bq/terraform/redis-cli in
TK-43 (wave-2 plan); gh, RUN_PREFIXES and the gradle task tables joined in
TK-55; flag-sensitive streaming forms stay in dedicated
hang_policy predicates (`_is_docker`, `_is_kubectl`, `_is_redis_monitor`)
because a plain prefix table cannot express them.

Family record schema:
  global_flags  -- boolean-only global flags allowed between head and verb
                   (exact token equality). Value-taking flags are deliberately
                   NOT listed here: the scan skips them via value_flags below
                   or stops at the first unknown token, so `vercel --token
                   list` (flag value that looks like a verb) can never be
                   mistaken for `vercel list`.
  value_flags   -- OPTIONAL: value-taking flags of the family. The effective
                   verb scan skips the flag plus its following token
                   (`kubectl -n prod get pods`); `=`-forms
                   (`--namespace=prod`) are skipped whole via the part before
                   `=` (the value never leaves the token, so a value equal to
                   a verb cannot fake a match - rewriter.py cargo precedent).
                   Absent means "no value flags declared" and the scan treats
                   every token as significant.
  ro_verbs      -- full verb sequences that are purely observational; the
                   rewriter auto-prefixes them with "actx ".
  ask_specs     -- T6 ask specs (ordered token subsequences) merged verbatim
                   into security_gate.T6_ASK_TABLE.
  stream_specs  -- streaming/interactive/secret-printing verb prefixes; the
                   hang policy refuses them (never-wrap, exit 125).

Qualification rule (N-F4): a verb is banned from ro_verbs when its family has
a sibling that writes a local file or prints secret values (`vercel env
pull`, `netlify env:get`, `wrangler secret put`, `fly secrets set`, `gcloud
secrets versions access`). Per the blocker review decision (Q2) every
env/variables/secret-like verb of every family goes to stream_specs: redaction
is pattern-based on key names and misses `KEY=postgres://prod:pw@host/db`.
Invariant: ro_verbs, ask_specs and stream_specs are pairwise disjoint as
tuple sets inside each family (tested).

Verb lists verified against the official CLI docs on 2026-09-05 (Vercel,
Netlify, Railway, Cloudflare Wrangler, Supabase, fly.io, gcloud); docker
joined in TK-41, kubectl and helm in TK-40 (wave-2 plan). Additions stay
conservative - when in doubt, leave the verb out.
"""

FAMILIES = {
    # vercel docs: global options (--debug/-d, --no-color, --non-interactive
    # are boolean; --cwd/--token/--scope/--project/--team take values);
    # `vercel env pull <file>` writes a local env file -> `env` never in RO.
    "vercel": {
        "global_flags": ("-d", "--debug", "--no-color", "--non-interactive"),
        "ro_verbs": (("whoami",), ("list",), ("logs",)),
        "ask_specs": (("deploy", "--prod"), ("remove",)),
        "stream_specs": (
            ("env",),
            ("logs", "-f"), ("logs", "--follow"),
            ("dev",),
        ),
    },
    # netlify docs: `env:get` prints variable values and `env:export` writes
    # a local .env -> the whole env family is never-wrap; `watch` waits for a
    # deploy; no boolean global flags worth skipping.
    "netlify": {
        "global_flags": (),
        "ro_verbs": (("status",), ("sites:list",)),
        "ask_specs": (("deploy",), ("delete",)),
        "stream_specs": (
            ("env",),
            ("env:get",), ("env:list",), ("env:set",), ("env:unset",),
            ("env:import",), ("env:export",), ("env:clone",),
            ("watch",),
            ("logs",),
            ("dev",),
        ),
    },
    # railway docs: `variables` prints environment values (secret-bearing),
    # `connect`/`ssh` are REPLs, `run` executes a local dev command, `logs`
    # follows deploy logs -> all never-wrap.
    "railway": {
        "global_flags": (),
        "ro_verbs": (("whoami",), ("status",), ("list",)),
        "ask_specs": (("up",), ("delete",), ("remove",), ("down",)),
        "stream_specs": (
            ("variables",),
            ("logs",),
            ("connect",),
            ("ssh",),
            ("run",),
        ),
    },
    # wrangler docs: `secret put` writes secret values and `secret bulk`
    # reads them -> secret family never-wrap; `tail` and logins are already
    # covered by hang_policy (_is_wrangler_tail, _is_login) - not duplicated.
    "wrangler": {
        "global_flags": (),
        "ro_verbs": (
            ("whoami",),
            ("deployments", "list"),
            ("deployments", "status"),
        ),
        "ask_specs": (("deploy",), ("publish",), ("delete",)),
        "stream_specs": (("secret",), ("secret:bulk",)),
    },
    # supabase docs: global boolean flags --debug/--experimental/--yes/
    # --create-ticket; `secrets set` mutates project secrets -> secrets
    # family never-wrap; `db reset` is a destructive ask (T6).
    "supabase": {
        "global_flags": ("--debug", "--experimental", "--yes", "--create-ticket"),
        "ro_verbs": (("status",), ("projects", "list")),
        "ask_specs": (("delete",), ("db", "reset")),
        "stream_specs": (("secrets",),),
    },
    # fly.io docs: top-level destructive verbs are `fly deploy` and
    # `fly apps destroy` (no top-level `release`/`delete`/`destroy` exist);
    # `fly logs` follows live logs, `fly ssh console`/`fly console` are REPLs,
    # `fly proxy` tunnels forever, `fly secrets`/`fly tokens` print secrets.
    "flyctl": {
        "global_flags": ("-i", "--interactive", "--verbose", "--json"),
        "ro_verbs": (("status",), ("apps", "list"), ("releases",)),
        "ask_specs": (("deploy",), ("apps", "destroy")),
        "stream_specs": (
            ("logs",),
            ("ssh",),
            ("proxy",),
            ("console",),
            ("secrets",),
            ("tokens",),
        ),
    },
    # gcloud docs: 2-token read-only sequences; `config` and `auth` families
    # are banned from RO by siblings (`config set` persists to a local file,
    # `auth print-access-token` prints a secret); `gcloud secrets versions
    # access` prints secret payloads -> secrets family never-wrap.
    "gcloud": {
        "global_flags": ("--quiet", "-q"),
        "ro_verbs": (("projects", "list"),),
        "ask_specs": (("delete",), ("undeploy",)),
        "stream_specs": (("secrets",),),
    },
    # docker (TK-41): global value flags (--context/-H/--host) are
    # deliberately NOT skipped here — the scan stops at the first unknown
    # token, so `docker --context prod ps` stays unrewritten (conservative;
    # the infra filter dispatches on effective verbs locally). Flag-sensitive
    # streaming forms (bare `docker stats`, `compose up` without -d,
    # `attach`, `logs -f`, `compose logs -f`) cannot be expressed as plain
    # prefixes and live in the dedicated hang_policy._is_docker predicate
    # (precedent: _is_wrangler_tail) — hence empty stream_specs.
    "docker": {
        "global_flags": (),
        "ro_verbs": (
            ("ps",), ("images",), ("logs",), ("inspect",),
            ("system", "df"),
            ("stats", "--no-stream"),
            ("compose", "ps"), ("compose", "logs"),
        ),
        # First 4 specs verbatim from the pre-TK-41 _T6_NON_CLOUD_ASK_TABLE
        # entry; volume rm/prune are new (TK-41).
        "ask_specs": (
            ("system", "prune"), ("rm",), ("rmi",), ("compose", "down"),
            ("volume", "rm"), ("volume", "prune"),
        ),
        "stream_specs": (),
    },
    # kubectl (TK-40). RO verbs are the observational set; `logs` without -f
    # was already rewritten pre-TK-40 (N-F12b) - the -f form is refused by
    # hang_policy._is_kubectl, not by this table. Watch flags (-w/--watch)
    # and secret/configmap object types are likewise never-wrap in
    # _is_kubectl (N-F4/N-F3a): base64 secret values dodge pattern redaction.
    # `-A/--all-namespaces` are boolean globals; the rest of the listed
    # flags take a value (`-n prod`, `--context ctx`, `--namespace=prod`).
    # ask_specs: the 4 pre-TK-40 non-cloud specs verbatim + ("exec",)
    # (REQ-02: shell escape bypassing every actx gate).
    "kubectl": {
        "global_flags": ("-A", "--all-namespaces"),
        "value_flags": ("-n", "--namespace", "--context", "--cluster",
                        "--kubeconfig"),
        "ro_verbs": (("get",), ("describe",), ("top",), ("events",), ("logs",)),
        "ask_specs": (("delete",), ("scale",), ("rollout", "undo"),
                      ("apply",), ("exec",)),
        "stream_specs": (),
    },
    # helm (TK-40). `helm template` renders a local chart (a --set secret is
    # already visible in argv) -> RO; `helm get values` prints DEPLOYED
    # values - the standard home of credentials - so it goes to stream_specs
    # by the wave-1 N-F4 qualification rule, never-wrap. ask_specs are the
    # pre-TK-40 non-cloud specs verbatim.
    "helm": {
        "global_flags": (),
        "ro_verbs": (("template",), ("get", "metadata"), ("list",),
                     ("show", "values"), ("show", "chart"), ("status",),
                     ("history",)),
        "ask_specs": (("uninstall",), ("rollback",)),
        "stream_specs": (("get", "values"),),
    },
    # bq (TK-43). Only the single-token `=`-forms of --format are declared
    # as boolean globals (conservative: the two-token `--format json` form
    # stops the scan -> no rewrite, safe); --debug_mode is boolean. The head
    # runs through the generic registry entry (_cloud_entry): JSON output
    # auto-detects on runner.run. `query` is RO only with --dry_run - the
    # executing form stays unwritten (TK-52 reviews an ask).
    "bq": {
        "global_flags": ("--format=json", "--format=prettyjson", "--debug_mode"),
        "ro_verbs": (("ls",), ("show",), ("head",), ("query", "--dry_run")),
        "ask_specs": (),
        "stream_specs": (),
    },
    # terraform (TK-43). RO verbs are the plan-inspection set; `plan -out`
    # persists a plan file that a later `terraform apply` executes without
    # re-reading the diff, and `state` mutates/pulls state (credentials
    # live in it) -> ask. Limitation (documented): the `-out=file` =-form
    # does not equal the "-out" token, so the token matcher misses it
    # (N-F1 red-gate 12 checks the caught form).
    "terraform": {
        "global_flags": (),
        "ro_verbs": (("plan",), ("validate",), ("show",), ("version",),
                     ("graph",)),
        "ask_specs": (("apply",), ("destroy",), ("state",), ("plan", "-out")),
        "stream_specs": (),
    },
    # redis-cli (TK-43). Real redis commands are upper-case but the
    # protocol is case-insensitive, so every entry carries its lower-case
    # twin (tested both ways) - a lowercase FLUSHALL/`config set` must not
    # evade the ask tier, a lowercase `get` must not dodge never-wrap.
    # GET prints arbitrary VALUES (Q2 wave-1 rule: pattern redaction
    # cannot catch value secrets) -> stream_specs, never-wrap; TK-52
    # reviews the reverse. MONITOR is NOT duplicated here - the dedicated
    # _is_redis_monitor predicate owns it (wrangler-tail precedent).
    "redis-cli": {
        "global_flags": (),
        "value_flags": ("-h", "--host", "-p", "--port", "-s", "--socket",
                        "-u", "--url", "-n"),
        "ro_verbs": (("EXISTS",), ("TTL",), ("TYPE",), ("SCAN",),
                     ("DBSIZE",), ("exists",), ("ttl",), ("type",),
                     ("scan",), ("dbsize",)),
        "ask_specs": (("FLUSHALL",), ("flushall",), ("FLUSHDB",),
                      ("flushdb",), ("config", "set"), ("CONFIG", "SET"),
                      ("Config", "Set")),
        "stream_specs": (("GET",), ("get",)),
    },
    # gh (TK-55 F2): every verb below verified against `gh <ns> --help`
    # (gh 2.100.0). ro_verbs are the observational sequences; ask_specs
    # carry every mutating subcommand of the covered namespaces. In NO
    # list (-> defer, never rewrite): `run download`/`release download`
    # write artifact files into cwd (N-F4 sibling rule), the `auth`/
    # `secret`/`variable` namespaces print or set credential material and
    # `api` is an arbitrary HTTP verb surface; the mixed read/write
    # sub-namespaces `repo autolink`/`repo deploy-key` stay out too.
    # `run watch` and `pr checks --watch` wait on remote state ->
    # stream_specs (never-wrap).
    "gh": {
        "global_flags": (),
        "value_flags": ("-R", "--repo"),
        "ro_verbs": (
            ("pr", "list"), ("pr", "view"), ("pr", "status"),
            ("pr", "diff"), ("pr", "checks"),
            ("issue", "list"), ("issue", "view"), ("issue", "status"),
            ("run", "list"), ("run", "view"),
            ("repo", "list"), ("repo", "view"),
            ("release", "list"), ("release", "view"),
            ("workflow", "list"), ("workflow", "view"),
            ("search",), ("gist", "list"),
        ),
        "ask_specs": (
            ("pr", "merge"), ("pr", "create"), ("pr", "close"),
            ("pr", "reopen"), ("pr", "comment"), ("pr", "edit"),
            ("pr", "review"), ("pr", "checkout"), ("pr", "ready"),
            ("pr", "lock"), ("pr", "unlock"),
            ("pr", "revert"), ("pr", "update-branch"),
            ("issue", "create"), ("issue", "comment"), ("issue", "close"),
            ("issue", "reopen"), ("issue", "delete"), ("issue", "edit"),
            ("issue", "transfer"), ("issue", "pin"), ("issue", "unpin"),
            ("issue", "lock"), ("issue", "unlock"), ("issue", "develop"),
            ("run", "delete"), ("run", "cancel"), ("run", "rerun"),
            ("repo", "create"), ("repo", "fork"), ("repo", "delete"),
            ("repo", "archive"), ("repo", "unarchive"), ("repo", "rename"),
            ("repo", "edit"), ("repo", "sync"), ("repo", "set-default"),
            ("repo", "clone"),
            ("release", "create"), ("release", "delete"),
            ("release", "edit"), ("release", "upload"),
            ("release", "delete-asset"),
            ("workflow", "run"), ("workflow", "enable"),
            ("workflow", "disable"),
            ("gist", "create"), ("gist", "edit"), ("gist", "delete"),
            ("gist", "rename"), ("gist", "clone"),
        ),
        "stream_specs": (
            ("run", "watch"), ("pr", "checks", "--watch"),
        ),
    },
}


def effective_verbs(argv):
    """Effective verb tokens of an argv: everything after the head with the
    family's boolean global_flags skipped (exact token equality) and its
    value_flags skipped together with their value token; `=`-forms
    (`--namespace=prod`) are skipped whole by the part before `=`, so a flag
    value can never impersonate a verb. Returns None when the head is not a
    declared family; [] for a bare family head. Pure: no imports, no I/O."""
    spec = FAMILIES.get(argv[0]) if argv else None
    if spec is None:
        return None
    value_flags = spec.get("value_flags", ())
    out = []
    i = 1
    n = len(argv)
    while i < n:
        tok = argv[i]
        if tok in spec["global_flags"]:
            i += 1
            continue
        if tok in value_flags:
            i += 2  # the flag and its separate value token
            continue
        if "=" in tok and tok.split("=", 1)[0] in value_flags:
            i += 1  # --flag=value: the value stays inside the token
            continue
        out.append(tok)
        i += 1
    return out


# Literal skip sets for unwrapping an `actx` prefix in security_gate
# (mirrors cli.py flag parsing: global flags, then an optional `run`
# literal, then leading run flags). Closed literal lists on purpose -
# NO generic startswith("-") skipping. `actx rewrite` / `actx hook` inputs
# are not argv of an executable command, so their literals are absent and
# unwrapping stops at them.
ACTX_GLOBAL_FLAGS = (
    "--raw", "--ultra-compact", "-v", "-vv", "-vvv", "--version", "--help", "-h",
)
ACTX_RUN_LITERAL = "run"
ACTX_RUN_FLAGS = ("--errors", "--failures", "--digest")


# Exec-prefixes whose argv continues with an inner command ("uv run tsc",
# "xcrun simctl erase"). Security gate unwraps these to the effective head;
# the rewriter uses the inner head for write-flag checks. Data only —
# both consumers share this table (single source, TK-55 F3/F4).
#
#   verb        -- required literal second token ("uv run ..."); None means
#                  the head invokes a tool directly (xcrun).
#   only_tool   -- when present, the inner head must equal it (xcrun is
#                  unwrapped only in front of simctl — conservative, the
#                  generic `xcrun <tool>` form stays opaque).
#   value_flags -- flags consuming the next token as their value.
#   bool_flags  -- single-token boolean flags.
# `--flag=value` forms of both are handled by the scanner itself.
RUN_PREFIXES = {
    # `uv run --help` (uv 0.9.x): every flag below verified as a real
    # value-taking or boolean flag of the run subcommand.
    "uv": {
        "verb": "run",
        "value_flags": (
            "--extra", "--no-extra", "--group", "--no-group",
            "--only-group", "--env-file",
            "--with", "--with-editable", "--with-requirements",
            "--package",
            "--index", "--default-index", "-i", "--index-url",
            "--extra-index-url", "-f", "--find-links",
            "--index-strategy", "--keyring-provider",
            "-P", "--upgrade-package", "--resolution", "--prerelease",
            "--fork-strategy", "--exclude-newer",
            "--reinstall-package", "--link-mode",
            "-C", "--config-setting",
            "--no-build-isolation-package", "--no-build-package",
            "--no-binary-package",
            "--cache-dir", "--refresh-package",
            "-p", "--python",
            "--color", "--allow-insecure-host",
            "--directory", "--project", "--config-file",
        ),
        "bool_flags": (
            "--all-extras", "--no-dev", "--no-default-groups",
            "--all-groups", "-m", "--module", "--only-dev",
            "--no-editable", "--exact", "--no-env-file",
            "--isolated", "--active", "--no-sync", "--locked",
            "--frozen", "-s", "--script", "--gui-script",
            "--all-packages", "--no-project",
            "--no-index",
            "-U", "--upgrade", "--no-sources",
            "--reinstall", "--compile-bytecode",
            "--no-build-isolation", "--no-build", "--no-binary",
            "-n", "--no-cache", "--refresh",
            "--managed-python", "--no-managed-python",
            "--no-python-downloads",
            "-q", "--quiet", "-v", "--verbose", "--native-tls",
            "--offline", "--no-progress", "--no-config",
            "-h", "--help",
        ),
    },
    # `xcrun --help` (Xcode CLT): --sdk/--toolchain take a value; the rest
    # are boolean lookup/log selectors.
    "xcrun": {
        "verb": None,
        "only_tool": "simctl",
        "value_flags": ("--sdk", "--toolchain"),
        "bool_flags": (
            "-l", "--log", "-f", "--find", "-r", "--run",
            "-n", "--no-cache", "-k", "--kill-cache",
            "--show-sdk-path", "--show-sdk-version",
            "--show-sdk-build-version", "--show-sdk-platform-path",
            "--show-sdk-platform-version", "--show-toolchain-path",
            "-v", "--verbose", "--version", "-h", "--help",
        ),
    },
}


def run_prefix_split(tokens: list[str]) -> tuple[list[str], list[str]] | None:
    """If tokens match a RUN_PREFIXES pattern, return (inner_argv, consumed).

    inner_argv starts at the inner command's head; consumed holds the
    skipped wrapper tokens (prefix flags and their values) so callers can
    keep them visible to token-level scans. Returns None when tokens do not
    match a run-prefix or the inner head cannot be located (unknown flag,
    missing inner command) — callers then keep the original tokens
    (fail-open).
    """
    if not tokens:
        return None
    # basename without os.path — cli_families keeps zero imports (hook/rewrite
    # import boundary); covers `/usr/bin/uv run ...` alongside bare `uv`.
    spec = RUN_PREFIXES.get(tokens[0].rsplit("/", 1)[-1])
    if spec is None:
        return None
    idx = 1
    if spec["verb"] is not None:
        if len(tokens) < 2 or tokens[1] != spec["verb"]:
            return None
        idx = 2
    only_tool = spec.get("only_tool")
    value_flags = spec.get("value_flags", ())
    bool_flags = spec.get("bool_flags", ())
    n = len(tokens)
    while idx < n:
        tok = tokens[idx]
        if tok in value_flags:
            idx += 2  # the flag and its separate value token
            continue
        if tok.startswith("-"):
            name = tok.split("=", 1)[0]
            if name in value_flags or name in bool_flags:
                idx += 1  # --flag=value / boolean flag: single token
                continue
            return None  # unknown flag: bail, keep the original tokens
        # First positional token is the inner command's head.
        if only_tool is not None and tok != only_tool:
            return None
        return tokens[idx:], tokens[:idx]
    return None


# Gradle task grammar (TK-55 F5): tasks are positional tokens, addressable
# as `name` or `:module:taskVariant`; flags are consumed per these tables.
GRADLE_VALUE_FLAGS = (
    "--tests", "-p", "--project-dir", "-b", "--build-file",
    "-c", "--settings-file", "-I", "--init-script",
    "-g", "--gradle-user-home", "--project-cache-dir",
    "--console", "--warning-mode", "--max-workers", "--priority",
    "--exclude-task", "-x", "--include-build",
    "--dependency-verification", "--configuration-cache-problems",
    "-P", "--project-prop", "-D", "--system-prop",
)
# `-P`/`-D` are also used attached (`-Pprop=v`, `-Dprop=v`): a token merely
# STARTING with one of these prefixes is skipped whole.
GRADLE_ATTACHED_VALUE_PREFIXES = ("-P", "-D")
GRADLE_BOOL_FLAGS = (
    "--offline", "--daemon", "--no-daemon", "--parallel", "--no-parallel",
    "-q", "--quiet", "-w", "--warn", "-i", "--info", "-d", "--debug",
    "-s", "--stacktrace", "-S", "--full-stacktrace",
    "--scan", "--no-scan", "--watch-fs", "--no-watch-fs",
    "-t", "--continuous", "--build-cache", "--no-build-cache",
    "--configure-on-demand", "--no-configure-on-demand",
    "--configuration-cache", "--no-configuration-cache",
    "--profile", "-m", "--dry-run", "--rerun-tasks",
    "--continue", "--no-continue", "--fail-fast",
    "-a", "--no-rebuild", "-u", "--no-search-upward",
    "--refresh-dependencies", "-v", "--version", "-h", "--help",
)
# Deliberately NOT declared — they fail closed as unknown flags:
# daemon-action flags (`--stop`, `--status`, `--foreground`) and the
# mutating `--write-locks`, `--update-locks`, `--write-verification-metadata`
# (they rewrite lockfiles/verification metadata, so they must never
# decorate an RO task scan).
GRADLE_RO_BASES = (
    "assemble", "build", "test", "check", "lint", "tasks",
    "dependencies", "dependencyinsight", "help", "properties",
    "projects", "components", "model",
)
GRADLE_ASK_MARKERS = (
    "publish", "upload", "clean", "sign", "deploy", "release", "push",
)


def gradle_task_class(token: str) -> str:
    """Classify a positional gradle task token -> "ask" | "ro" | "unknown".

    Uses the last `:`-segment (":app:assembleDebug" -> "assembleDebug").
    ASK wins over RO: a segment containing a publish/clean-class marker
    (substring, case-insensitive) is ask even when it starts with an RO
    base ("assembleAndPublish"). RO = segment starts with an RO base.
    Anything else is "unknown"."""
    segment = token.rsplit(":", 1)[-1].lower()
    if any(marker in segment for marker in GRADLE_ASK_MARKERS):
        return "ask"
    if any(segment.startswith(base) for base in GRADLE_RO_BASES):
        return "ro"
    return "unknown"
