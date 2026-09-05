"""Declarative table of cloud CLI families (TK-39).

Pure data, zero imports: rewriter, security_gate and hang_policy all read it
directly, so the cheap hook/rewrite import boundary must not gain transitive
modules. Connecting a new cloud CLI is a data edit here, not a new predicate.

Family record schema:
  global_flags  -- boolean-only global flags allowed between head and verb
                   (exact token equality). Value-taking flags are deliberately
                   NOT listed: the scan stops at the first unknown token, so
                   `vercel --token list` (flag value that looks like a verb)
                   can never be mistaken for `vercel list`.
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
Netlify, Railway, Cloudflare Wrangler, Supabase, fly.io, gcloud); additions
stay conservative - when in doubt, leave the verb out.
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
}

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
