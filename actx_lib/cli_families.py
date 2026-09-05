"""Declarative table of CLI families (TK-39; docker TK-41, kubectl/helm TK-40).

Pure data + one pure function (effective_verbs), zero imports: rewriter,
security_gate and hang_policy all read it directly, so the cheap hook/rewrite
import boundary must not gain transitive modules. Connecting a new CLI family
is a data edit here, not a new predicate. Not only cloud CLIs live here:
docker joined in TK-41 and kubectl/helm in TK-40; their flag-sensitive
streaming forms stay in dedicated hang_policy predicates (`_is_docker`,
`_is_kubectl`) because a plain prefix table cannot express them.

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
