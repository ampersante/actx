"""TK-60 fix-wave STEP-G/W6 acceptance helper: mechanical cross-check of
`actx_lib.rewrite_spec.HEAD_SPECS` (the closed-grammar rewriter's per-head
admitted-flag tables) against what the INSTALLED CLI itself documents, via
`--help`/`-h`/`man`/a deliberately-invalid-flag error dump - never by eye.

For every (head, verb-path) in the HELP table below that has a runnable help
source on this machine, this script extracts every flag TOKEN the tool's own
output mentions, then reports two disjoint things:

  UNKNOWN       - flags the spec ADMITS that the tool's own docs never
                  mention under any spelling this script recognizes. This is
                  the actionable list: each entry is either a typo/
                  hallucinated flag (a real spec bug - fix the spec) or a
                  real flag this script's help source/extraction still
                  cannot see (a script gap - extend the source, don't
                  hand-wave the spec). MUST be empty, or every remaining
                  entry must be independently, mechanically explained below
                  as a documented, cited platform difference (this box ships
                  BSD/Darwin coreutils + BSD grep + BSD find; the spec
                  intentionally also admits well-established GNU spellings
                  for users on Linux/Homebrew-coreutils, per the `gls`
                  alias and the grep/find GNU-only flag comments already in
                  rewrite_spec.py).
  UNCLASSIFIED  - flags the tool documents that the spec neither admits nor
                  (elsewhere) explicitly excludes. Informational only, never
                  fails - a review list for someone widening admission, not
                  a defect in what's already admitted.

Extraction is deliberately layered past naive regex-on-help-text, because
real CLI help/man text defeats a naive scrape in specific, recurring ways
this script corrects for (each cited at its own site below):
  - a flag mentioned only inside a sentence picks up the sentence-final
    "." (`--maxdepth.`, `--cached.`) - both the raw and the period-stripped
    spelling are recorded so this never hides a real flag as "unknown".
  - BSD man pages enumerate single-character short flags as one bracket
    cluster in SYNOPSIS (`ls [-@ABC...]`) rather than one line per flag -
    every character in such a cluster is recorded as `-c`.
  - git's own `-h`/error-usage text (and this script's own deliberately
    invalid `--actx-flag-probe-...` extra invocation, which upgrades many
    git verbs' "unknown option" error into the FULL per-flag reference)
    spells boolean toggles as `--[no-]xxx` - both `--xxx` and `--no-xxx`
    are recorded.
  - `git show`/`git log` share most of their flags in git's own
    implementation, and both further share diff-formatting flags with
    `git diff`, but `git-show(1)`/`git-log(1)`'s own man pages explicitly
    say "see git-log(1)"/"see git-diff(1)" instead of repeating them -
    git-log's and git-diff's man pages are merged into git show's help
    source, and git-diff's into git log's, for exactly that reason.
  - a tool whose short flag isn't alphanumeric documents it as `-X, --long`
    at the start of its own help line (ripgrep: `-., --hidden`) - FLAG_RE
    requires a letter right after the dash and never sees these; a second,
    narrowly-anchored regex records the punctuation short form too.
  - sqlite3's own shell strips 1-2 leading dashes generically before
    comparing flag names (already documented in actx_lib/sql_verbs.py) -
    `-x`/`--x` are treated as the same flag when checking sqlite3.
  - a few `find` primaries (`-newerXY`) are a templated FAMILY the man page
    describes in prose rather than spelling out every combination - the
    valid X/Y letter sets are transcribed from that prose (cited at the
    definition) and the combinations generated, not typed by hand.

Usage:
    python3 tools/flag_inventory.py [<repo-root>]

<repo-root> defaults to this script's own repository (two directories up
from tools/). Stdlib only (subprocess/re/importlib); reads no network,
installs nothing - every help source is a binary/man page already on PATH.
A tool missing from PATH prints "HELP UNAVAILABLE" for its row and is
skipped, never crashes the run.
"""
import importlib
import os
import re
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.dirname(SCRIPT_DIR)
REPO_ROOT = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ROOT

sys.path.insert(0, REPO_ROOT)
spec_mod = importlib.import_module("actx_lib.rewrite_spec")

FLAG_RE = re.compile(r"(?<![\w/-])(--?[A-Za-z][A-Za-z0-9._-]*)")
# git's own `--[no-]xxx` boolean-toggle spelling (seen in `git <verb> -h` and
# in the rich per-flag usage dump a deliberately-invalid long option
# triggers on several verbs, e.g. `git add --actx-flag-probe-...` ->
# "--[no-]auto-advance   auto advance to the next file..."). Both spellings
# are real, admitted flags; the bracket notation itself is never a token.
GIT_NO_TOGGLE_RE = re.compile(r"--\[no-\]([A-Za-z][A-Za-z0-9-]*)")
# BSD-style SYNOPSIS bracket cluster of single-character short flags, e.g.
# `ls [-@ABCFGHILOPRSTUWabcdefghiklmnopqrstuvwxy1%,]` (man ls, this box,
# 2026-09-27) - every character between the brackets is its own `-c` flag.
# Constrained to alnum + the specific punctuation BSD man pages actually use
# in such clusters (`@%,`) so it never fires on an unrelated `[num]`-style
# placeholder elsewhere in prose.
BSD_CLUSTER_RE = re.compile(r"\[-([A-Za-z0-9@%,]{2,})\]")
# `-X, --long-name` at the start of a help line, where X is a single
# PUNCTUATION character (never a letter/digit - those already match
# FLAG_RE) - the common getopt-style two-column short/long convention used
# by tools whose short flag isn't alphanumeric (ripgrep: `-., --hidden`,
# `rg --help` line 625, this box, 2026-09-27). Anchored to line-start plus
# the immediately-following ", --" so it can only ever fire on this exact
# documentation idiom, never on an unrelated mid-sentence "-. " or a
# hyphenated word.
PUNCT_SHORT_RE = re.compile(r"^[ \t]{0,8}-([^\sA-Za-z0-9-])[ \t]*,[ \t]*--", re.MULTILINE)

# find's `-newerXY` family (man find, this box, 2026-09-27): "True if the
# current file has a more recent last access time (X=a), inode creation
# time (X=B), change time (X=c), or modification time (X=m) than the last
# access time (Y=a), inode creation time (Y=B), change time (Y=c), or
# modification time (Y=m) of file. In addition, if Y=t, then file is
# instead interpreted as a direct date specification." - a template, not a
# literal enumeration; every legal combination is generated from those two
# transcribed letter sets, never hand-typed as individual flag strings.
_FIND_NEWER_X = "aBcm"
_FIND_NEWER_Y = "aBcmt"
FIND_NEWERXY_FLAGS = frozenset(
    "-newer" + x + y for x in _FIND_NEWER_X for y in _FIND_NEWER_Y
)

# head/verb path -> argv that prints its help (absolute binaries; stdlib
# only). For every git verb, a deliberately-invalid long option is appended
# as an EXTRA, harmless probe: unsupported verbs just add a one-line "fatal:
# unrecognized argument" (zero new flags, no harm); verbs on git's newer
# parse-options usage banner (status/add/commit/diff/branch/push/pull/fetch/
# blame, live-checked git 2.50.1 "Apple Git-155", 2026-09-27) upgrade to the
# FULL per-flag reference, catching real flags (`--auto-advance`,
# `--ahead-behind`) that don't appear in `-h` or the man page at all - live-
# verified: `git add --dry-run --auto-advance` and `git commit --dry-run
# --ahead-behind` both exit 0 (accepted), while `git add
# --totally-bogus-flag-xyz` exits 129 with "error: unknown option" (the
# probe technique actually distinguishes real-but-underdocumented flags from
# typos, it doesn't just admit everything).
_GIT_PROBE = "/usr/bin/git {v} --actx-flag-probe-does-not-exist 2>&1"
HELP = {
    ("git", v): ["/bin/sh", "-c",
                 f"/usr/bin/git {v} -h; man git-{v} 2>/dev/null | col -b; " + _GIT_PROBE.format(v=v)]
    for v in ("status", "log", "diff", "show", "blame", "rev-parse", "add",
              "commit", "push", "pull", "fetch", "branch")
}
# git-log(1)/git-show(1) both explicitly defer to git-diff(1) for the
# diff-formatting options they share ("git log -p"/"git show" walk the same
# diff machinery), AND git-show(1) additionally defers to git-log(1) itself
# ("git show" on a range walks history the same way "git log" does) - both
# man pages cross-reference "git-diff(1)" repeatedly (live-checked, this
# box, 2026-09-27) and git-show(1) never itself documents e.g.
# --author/--decorate-refs/--since/--staged; git-diff(1) is the only source
# that documents "--staged is a synonym" for --cached at all. `git show
# --actx-flag-probe-...` falls back to the old one-line "fatal: unrecognized
# argument" (no rich per-flag dump for this verb, unlike add/commit/status).
HELP[("git", "log")] = ["/bin/sh", "-c",
                         "/usr/bin/git log -h; man git-log 2>/dev/null | col -b; "
                         "man git-diff 2>/dev/null | col -b; " + _GIT_PROBE.format(v="log")]
HELP[("git", "show")] = ["/bin/sh", "-c",
                          "/usr/bin/git show -h; man git-show 2>/dev/null | col -b; "
                          "man git-log 2>/dev/null | col -b; "
                          "man git-diff 2>/dev/null | col -b; " + _GIT_PROBE.format(v="show")]
HELP.update({
    ("grep",): ["/bin/sh", "-c", "man grep | col -b"],
    ("rg",): ["/opt/homebrew/bin/rg", "--help"],
    ("ls",): ["/bin/sh", "-c", "man ls | col -b"],
    ("find",): ["/bin/sh", "-c", "man find | col -b"],
    ("head",): ["/bin/sh", "-c", "man head | col -b"],
    ("tail",): ["/bin/sh", "-c", "man tail | col -b"],
    ("sort",): ["/bin/sh", "-c", "man sort | col -b"],
    ("uniq",): ["/bin/sh", "-c", "man uniq | col -b"],
    ("wc",): ["/bin/sh", "-c", "man wc | col -b"],
    ("cat",): ["/bin/sh", "-c", "man cat | col -b"],
    ("sqlite3",): ["/bin/sh", "-c", "/usr/bin/sqlite3 --help 2>&1 | sed -E 's/-\\[no\\]([a-z]+)/-\\1 -no\\1/'"],
    ("docker",): ["/bin/sh", "-c", "for c in ps images logs inspect stats 'system df' 'compose ps' 'compose logs'; do /usr/local/bin/docker $c --help; done; /usr/local/bin/docker --help"],
    # kubectl: help is pooled from every RO verb the family table actually
    # shares its flags across (cli_families.py CLI_FAMILIES["kubectl"]
    # ro_verbs = get/describe/top/events/logs, plus `wait` which
    # rewrite_spec's FAMILY_EXTRAS value table admits `--for` for even
    # though `wait` itself isn't an ro_verb) - `kubectl get/logs --help`
    # alone (the old source) never mentions `top`'s own flags
    # (--containers/--show-swap/--sum/--use-protocol-buffers), `wait`'s
    # `--for`, or `events`'s `--types`; all six live-confirmed present in
    # their own verb's `--help`, 2026-09-27.
    ("kubectl",): ["/bin/sh", "-c",
                   "/usr/local/bin/kubectl options; "
                   "/usr/local/bin/kubectl get --help; "
                   "/usr/local/bin/kubectl describe --help; "
                   "/usr/local/bin/kubectl top pod --help; "
                   "/usr/local/bin/kubectl top node --help; "
                   "/usr/local/bin/kubectl events --help; "
                   "/usr/local/bin/kubectl wait --help; "
                   "/usr/local/bin/kubectl logs --help"],
    ("gh",): ["/bin/sh", "-c", "for c in 'pr list' 'pr view' 'pr diff' 'issue list' 'run list' 'run view'; do /opt/homebrew/bin/gh $c --help; done"],
})


def _add_with_period_variant(documented, tok):
    """Records `tok` as documented, plus its sentence-final-period-stripped
    form when it ends in one (`--maxdepth.` -> also `--maxdepth`) - see
    module docstring. Never removes information, only adds the normalized
    companion, so a flag that legitimately ends in "." (none known, but
    nothing here assumes there can't be one) is never lost."""
    documented.add(tok)
    if tok.endswith(".") and len(tok) > 1:
        documented.add(tok.rstrip("."))


def help_flags(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=20,
                           stdin=subprocess.DEVNULL)
    except Exception as exc:  # noqa: BLE001 - report, don't crash
        return None, str(exc)
    text = (p.stdout or "") + (p.stderr or "")
    documented = set()
    for m in FLAG_RE.findall(text):
        _add_with_period_variant(documented, m.split("=", 1)[0])
    for name in GIT_NO_TOGGLE_RE.findall(text):
        documented.add("--" + name)
        documented.add("--no-" + name)
    for cluster in BSD_CLUSTER_RE.findall(text):
        for ch in cluster:
            documented.add("-" + ch)
    for ch in PUNCT_SHORT_RE.findall(text):
        documented.add("-" + ch)
    if not documented:
        # An empty inventory is a failed source, never "the tool has no flags".
        return None, f"no flags extracted (exit {p.returncode})"
    return documented, None


# Admitted flags the local help cannot show, each a documented platform or
# version difference - the ONLY UNKNOWN entries that do not fail the run.
# GNU coreutils/grep spellings (https://www.gnu.org/software/coreutils/manual,
# https://www.gnu.org/software/grep/manual): this box ships BSD tools, the
# specs deliberately also admit the GNU forms agents use on Linux.
_GNU = "GNU coreutils/grep manual"
PLATFORM_CITED = {
    "cat": ({"--help", "--number", "--number-nonblank", "--show-all", "--show-ends",
             "--show-nonprinting", "--show-tabs", "--squeeze-blank", "--version",
             "-A", "-E", "-T"}, _GNU),
    "grep": ({"--exclude-from", "--perl-regexp", "-P"}, _GNU),
    "head": ({"--help", "--quiet", "--silent", "--verbose", "--version",
              "--zero-terminated", "-q", "-v", "-z"}, _GNU),
    "ls": ({"--all", "--almost-all", "--author", "--block-size", "--classify",
            "--dereference", "--dereference-command-line",
            "--dereference-command-line-symlink-to-dir", "--directory", "--dired",
            "--escape", "--file-type", "--format", "--full-time",
            "--group-directories-first", "--help", "--hide", "--hide-control-chars",
            "--human-readable", "--hyperlink", "--ignore", "--ignore-backups",
            "--indicator-style", "--inode", "--kibibytes", "--literal", "--no-group",
            "--numeric-uid-gid", "--quote-name", "--quoting-style", "--recursive",
            "--reverse", "--show-control-chars", "--si", "--size", "--sort",
            "--tabsize", "--time", "--time-style", "--version", "--width", "--zero"}, _GNU),
    "tail": ({"--help", "--version", "--zero-terminated", "-z"}, _GNU),
    "uniq": ({"--check-chars", "--group", "--help", "--version",
              "--zero-terminated", "-w", "-z"}, _GNU),
    "wc": ({"--bytes", "--chars", "--files0-from", "--help", "--lines",
            "--max-line-length", "--total", "--version", "--words"}, _GNU),
    # git-add(1) in git >= 2.51 documents --[no-]auto-advance; Apple git 2.50
    # on this box predates it.
    ("git", "add"): ({"--auto-advance"}, "git-add(1), git >= 2.51"),
}


def spec_flags(level):
    """All flag spellings a spec level admits (names only)."""
    out = set()
    for field in ("bool", "value", "optional"):
        vals = getattr(level, field, None) if not isinstance(level, dict) else level.get(field)
        if vals:
            out |= {str(f).split("=", 1)[0] for f in vals}
    return out


def find_level(path):
    heads = getattr(spec_mod, "HEAD_SPECS")
    lvl = heads.get(path[0])
    for verb in path[1:]:
        if lvl is None:
            return None
        verbs = lvl.get("verbs") if isinstance(lvl, dict) else getattr(lvl, "verbs", None)
        lvl = (verbs or {}).get(verb)
    return lvl


total_unknown = 0
uncited = 0
unavailable = 0
for path, argv in sorted(HELP.items()):
    lvl = find_level(path)
    if lvl is None:
        print(f"{' '.join(path):20} NO SPEC")
        continue
    documented, err = help_flags(argv)
    if documented is None:
        unavailable += 1
        print(f"{' '.join(path):20} HELP UNAVAILABLE: {err}")
        continue
    admitted = spec_flags(lvl)
    head = path[0]

    def known(f, documented=documented, head=head):
        if f in documented or re.fullmatch(r"-\d+", f) or f in ("!", "--"):
            return True
        # find's -newerXY family (see FIND_NEWERXY_FLAGS docstring above).
        if head == "find" and f in FIND_NEWERXY_FLAGS:
            return True
        # sqlite3's shell strips 1-2 leading dashes generically before
        # comparing flag names (actx_lib/sql_verbs.py) - `-x`/`--x` are one
        # flag; check the other dash-count spelling too.
        if head == "sqlite3" and f.startswith("-"):
            name = f.lstrip("-")
            if ("-" + name) in documented or ("--" + name) in documented:
                return True
        # short cluster spellings listed in specs (-la) are covered if each letter is documented
        if re.fullmatch(r"-[A-Za-z]{2,}", f) and all(("-" + c) in documented for c in f[1:]):
            return True
        # --long / --no-long pairs
        if f.startswith("--no-") and ("--" + f[5:]) in documented:
            return True
        return False

    unknown = sorted(f for f in admitted if not known(f))
    unclassified = sorted(f for f in documented - admitted)
    cited_flags, source = PLATFORM_CITED.get(path if len(path) > 1 else head, (set(), ""))
    not_cited = [f for f in unknown if f not in cited_flags]
    total_unknown += len(unknown)
    uncited += len(not_cited)
    print(f"{' '.join(path):20} admitted={len(admitted):3} documented={len(documented):3} "
          f"UNKNOWN={unknown}" + (f" (cited: {source})" if unknown and not not_cited else ""))
    if not_cited:
        print(f"{'':20} UNCITED={not_cited}")
    print(f"{'':20} not-admitted-from-help={len(unclassified)}: {' '.join(unclassified)[:300]}")
print("TOTAL UNKNOWN:", total_unknown, "| UNCITED (must be 0):", uncited,
      "| HELP UNAVAILABLE (must be 0):", unavailable)
sys.exit(1 if uncited or unavailable else 0)
