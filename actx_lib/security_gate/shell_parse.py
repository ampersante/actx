"""actx security gate - structural shell parser (TK-73).

parse_command() reads a command string once, by shell rules, and returns
what the gate must evaluate in addition to its line-based path:

* units - the simple commands, each in a canonical single-line form that
  shlex.split accepts (literal segments decoded, literal-only quoted words
  re-quoted with shlex.quote, newline-like characters inside literals
  turned into spaces, quote-bearing substitution bodies replaced by ':',
  redirection operators as separate tokens); dialect variants of a unit
  (zsh `=cmd`, bash brace expansion, `$"..."`) follow it with variant_of
  set;
* nested - texts the shell executes in another way than a unit shows
  them (substitution and process-substitution bodies, the alternative
  `$( (...) )` reading of arithmetic, a here-string fed to a shell);
* heredoc_body_lines - every heredoc body line, stripped and without
  backslashes, so the caller can keep its line-based verdict for them.

Anything outside the closed grammar below yields None; the function never
raises. The parser only ADDS evaluations: it never removes text from the
caller's own line-based path.
"""

import itertools
import re
import shlex
from collections import namedtuple

from .common import _ENV_VALUE_OPTIONS, _WRAPPER_COMMANDS, _unwrap_tokens

__all__ = ["Unit", "Nested", "ParsedCommand", "parse_command", "extract_substitutions"]


# Immutable records as namedtuples: `dataclasses` costs ~6 ms of import time
# on the hook path, a namedtuple costs nothing.
# Unit: sep_before is str | None; variant_of int | None; multiline tuple[str, ...]
# (word values with a quote, backslash or newline-like char; see _RE_BODY_CHARS).
Unit = namedtuple(
    "Unit", ("text", "pos", "sep_before", "variant_of", "dyn_head", "multiline"),
    defaults=(None, False, ()),
)
Nested = namedtuple("Nested", ("text", "kind", "pos"))
# units: list[Unit]; nested: list[Nested]; heredoc_body_lines: frozenset[str].
ParsedCommand = namedtuple("ParsedCommand", ("units", "nested", "heredoc_body_lines", "canonical"))


_MAX_DEPTH = 32
_MAX_VARIANTS = 64
# Work per parse: nesting constructs entered, words read and characters
# scanned by arithmetic attempts. A failed `$((` attempt is re-read as `$(`, which
# doubles the work per level; the budget turns that into None (the caller's
# fallback) instead of exponential time.
_MAX_STEPS = 6000
_FEATURES = ("brace", "eq", "dollar")
# Same set as the shell-wrapper branch of t1_paths._check_sensitive_paths.
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "busybox"})
_NL_LIKE = "\n\r\x0b\x0c\x85\u2028\u2029"
_NL_TO_SPACE = str.maketrans(dict.fromkeys(_NL_LIKE, " "))
# Control characters other than \t \n \r \x0b \x0c (and DEL) are unsupported.
_RE_BAD_CTRL = re.compile(r"[\x00-\x08\x0e-\x1f\x7f]")
# A substitution body with one of these is neutralised to ':' in a unit
# (`${...}` keeps its parameter name: `${NAME:}`).
# Unit.multiline holds every decoded word value that contains a quote, a
# backslash or a newline-like character: the canonical unit text re-quotes
# such a value (shlex.quote glues `'"'"'`), which the line-based checks
# mis-tokenise, so the caller also judges the value itself as a command line
# when a shell runs it (INV-10). The name is historical.
_RE_BODY_CHARS = re.compile("['\"\\\\" + _NL_LIKE + "]")
_RE_PARAM_NAME = re.compile(r"[#!]?[A-Za-z0-9_]*")
_RE_QUOTY = re.compile("['\"`\\\\" + _NL_LIKE + "]")
# Unquoted word characters: everything but blanks, newline, operators,
# quotes, backslash, `$` and backtick. \r \x0b \x0c \x85 U+2028 U+2029 are
# word characters for the shell, so they are not excluded here.
_RE_LIT_RUN = re.compile(r"[^ \t\n;&|()<>'\"\\$`]+")
_RE_COND_RUN = re.compile(r"[^ \t\n;&|()<>'\"\\$`]+")
_RE_DQ_RUN = re.compile(r'[^"\\$`]+')
_RE_PARAM_RUN = re.compile(r"[^{}'\"\\$`]+")
_RE_ARITH_RUN = re.compile(r"[^()'\"\\$`\n]+")
_RE_ANSI_RUN = re.compile(r"[^'\\]+")
_RE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Options of a wrapper that take the next word as their value (the value is
# an operand, not the command word); env's are shared with common.
_WRAPPER_VALUE_OPTIONS = {
    "env": _ENV_VALUE_OPTIONS,
    "timeout": {"-k", "-s", "--kill-after", "--signal"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p", "-P", "-u", "--class", "--classdata"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    "xargs": {"-n", "-P", "-I", "-L", "-s", "-d", "-E", "-a", "-l"},
    "parallel": {"-j", "-n", "-N", "-a"},
}
_RE_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
_RE_ARRAY_PREFIX = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
_RE_FD_PREFIX = re.compile(r"[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\}")
_RE_DURATION = re.compile(r"^\d+[smhd]?$")
_RE_EQ_CMD = re.compile(r"=[A-Za-z0-9_]")
_RE_COPROC_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*[ \t]+(?=\{|\(|(?:if|while|until|for|case|select|\[\[)(?:[ \t\n;&|()<>]|$))"
)
_RE_ESAC = re.compile(r"esac(?=[ \t\n;&|()<>]|$)")
_RE_OCTAL = re.compile(r"[0-7]{1,3}")
_RE_HEX = {"x": re.compile(r"[0-9A-Fa-f]{1,2}"), "u": re.compile(r"[0-9A-Fa-f]{1,4}"),
           "U": re.compile(r"[0-9A-Fa-f]{1,8}")}
_RE_SIMPLE_BRACE = re.compile(r"([^{}]*)\{([^{},]*(?:,[^{},]*)+)\}([^{}]*)")
_RE_SEQ = re.compile(r"(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?|([A-Za-z])\.\.([A-Za-z])(?:\.\.(-?\d+))?")
_REDIR_OPS = ("<<<", "<<-", "<<", "<>", "<&", "<", ">>", ">|", ">&", ">")
_ANSI_SIMPLE = {
    "n": "\n", "t": "\t", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f",
    "v": "\v", "r": "\r", "\\": "\\", "'": "'", '"': '"', "?": "?",
}
# Leading reserved words stripped from a unit; command position continues.
_STRIP_WORDS = frozenset({"if", "then", "elif", "else", "while", "until", "do", "!", "nocorrect", "noglob"})
_RESERVED = frozenset({
    "if", "then", "elif", "else", "fi", "while", "until", "do", "done", "case", "esac",
    "for", "select", "in", "function", "coproc", "repeat", "nocorrect", "noglob", "time",
    "{", "}", "!", "[[", "]]",
})
# Reserved words still recognised right after a compound command closes.
_AFTER_CLOSE_WORDS = frozenset({"}", "fi", "done", "esac", "then", "do", "else", "elif"})


class _Unsupported(Exception):
    """A construct outside the closed grammar: parse_command returns None."""


# A word piece: (kind, render, value, quoted, dollar_string).
# kind "L" - literal (render: unit text; value: decoded text; quoted: the
# segment was quoted or escaped); kind "X" - contains an expansion (value:
# literal parts decoded, expansions as their source text). dollar_string
# marks a `$"..."` segment (INV-11 variant).


def _lit(text, quoted=False):
    return ("L", text, text, quoted, False)


def _value(pieces):
    return "".join(p[2] for p in pieces)


def _is_literal(pieces):
    return all(p[0] == "L" for p in pieces)


def _render(pieces):
    if _is_literal(pieces):
        if any(p[3] for p in pieces):
            value = _value(pieces).translate(_NL_TO_SPACE)
            quoted = shlex.quote(value)
            # A quoted reserved word is a command name; keep it quoted so
            # the canonical form reads the same way.
            return "'" + value + "'" if quoted in _RESERVED else quoted
        return "".join(p[1] for p in pieces)
    return "".join(p[1] for p in pieces)


class _Word:
    __slots__ = ("pieces", "raw", "start", "variants_ok", "kw")

    def __init__(self, pieces, raw, start, variants_ok=True):
        self.pieces = pieces
        self.raw = raw
        self.start = start
        self.variants_ok = variants_ok
        # The text of an unquoted literal word (reserved words, fd
        # prefixes; `\`+newline already removed), else None.
        self.kw = _value(pieces) if all(p[0] == "L" and not p[3] for p in pieces) else None

    def plain(self):
        return self.kw is not None


class _Ctx:
    __slots__ = ("nested", "heredoc_lines", "variants", "no_alt", "steps")

    def __init__(self, no_alt=False):
        self.nested = []
        self.heredoc_lines = set()
        self.variants = 0
        self.no_alt = no_alt
        self.steps = 0


class _Parser:
    def __init__(self, text, ctx, base=0, depth=0, in_sub=0):
        self.s = text
        self.n = len(text)
        self.i = 0
        self.ctx = ctx
        self.base = base
        self.depth = depth
        self.in_sub = in_sub
        self.pending = []
        self.sep = None
        self.term = None

    # -- helpers -------------------------------------------------------

    def _enter(self):
        self.depth += 1
        self.ctx.steps += 1
        if self.depth > _MAX_DEPTH or self.ctx.steps > _MAX_STEPS:
            raise _Unsupported("depth or step budget")

    def _blanks(self):
        s, n, i = self.s, self.n, self.i
        while i < n:
            c = s[i]
            if c == " " or c == "\t":
                i += 1
            elif c == "\\" and i + 1 < n and s[i + 1] == "\n":
                i += 2
            else:
                break
        self.i = i

    def _blanks_nl(self):
        while True:
            self._blanks()
            if self.i >= self.n:
                return
            c = self.s[self.i]
            if c == "\n":
                self.i += 1
                self._heredocs()
            elif c == "#":
                self._comment()
            else:
                return

    def _add_nested(self, text, kind, pos):
        if self.in_sub == 0:
            self.ctx.nested.append(Nested(text, kind, self.base + pos))

    # -- lists of commands ---------------------------------------------

    def parse_list(self, closer):
        """Parse commands until EOF (closer None), an unmatched ')' (closer
        ')') or a case-arm end (closer 'case'; self.term is ';;' or
        'esac'). Returns unit records (only built when in_sub == 0)."""
        s, n = self.s, self.n
        units = []
        cur = []
        cur_sep = [None]
        parens = 0
        braces = 0
        closed = False

        def finish():
            nonlocal cur
            if cur and self.in_sub == 0:
                units.extend(self._build(cur, cur_sep[0]))
            cur = []

        def add(item):
            if not cur:
                cur_sep[0] = self.sep
                self.sep = None
            cur.append(item)

        while True:
            self._blanks()
            i = self.i
            if i >= n:
                if closer is not None or parens or braces or self.pending:
                    raise _Unsupported("unterminated")
                finish()
                return units
            c = s[i]
            if c == "#":
                self._comment()
                continue
            if c == "\n":
                finish()
                closed = False
                self.sep = "\n"
                self.i = i + 1
                self._heredocs()
                continue
            if c == ";":
                if s.startswith(";;", i) or s.startswith(";&", i) or s.startswith(";|", i):
                    if closer != "case" or parens or braces:
                        raise _Unsupported("case terminator")
                    finish()
                    self.i = i + (3 if s.startswith(";;&", i) else 2)
                    self.sep = ";"
                    self.term = ";;"
                    return units
                finish()
                closed = False
                self.sep = ";"
                self.i = i + 1
                continue
            if c == "&":
                if s.startswith("&&", i):
                    finish()
                    closed = False
                    self.sep = "&&"
                    self.i = i + 2
                    self._blanks_nl()
                    continue
                if s.startswith("&>", i):
                    self.i = i
                    add(self._redirect("", ("&>>", "&>")))
                    continue
                finish()
                closed = False
                self.sep = "&"
                # zsh `&|` / `&!`: background and disown.
                self.i = i + (2 if s.startswith("&|", i) or s.startswith("&!", i) else 1)
                continue
            if c == "|":
                finish()
                closed = False
                if s.startswith("||", i):
                    self.sep, self.i = "||", i + 2
                elif s.startswith("|&", i):
                    self.sep, self.i = "|&", i + 2
                else:
                    self.sep, self.i = "|", i + 1
                self._blanks_nl()
                continue
            if c == "(":
                if closed:
                    raise _Unsupported("( after compound")
                if self._cmdpos(cur):
                    j = i + 1
                    while j < n and s[j] in " \t":
                        j += 1
                    if j < n and s[j] == ")":
                        # zsh anonymous function `() { ...; }`: the body runs.
                        self.i = j + 1
                        self._blanks_nl()
                        continue
                    if s.startswith("((", i):
                        arith = self._arith(i, dollar=False)
                        if arith is not None:
                            add(("w", _Word([_lit(arith)], arith, i, False)))
                            closed = True
                            continue
                    self._enter()
                    parens += 1
                    self.i = i + 1
                    continue
                if len(cur) == 1 and cur[0][0] == "w" and cur[0][1].plain():
                    j = i + 1
                    while j < n and s[j] in " \t":
                        j += 1
                    if j < n and s[j] == ")":
                        # Function definition `name () body`: the body is
                        # parsed as commands; the name is not a command.
                        cur = []
                        self.i = j + 1
                        self._blanks_nl()
                        continue
                raise _Unsupported("unexpected (")
            if c == ")":
                if parens:
                    finish()
                    parens -= 1
                    self.depth -= 1
                    closed = True
                    self.i = i + 1
                    continue
                if closer == ")" and not braces:
                    if self.pending:
                        raise _Unsupported("heredoc without a body inside a substitution")
                    finish()
                    self.i = i + 1
                    return units
                raise _Unsupported("unexpected )")
            if (c == "<" or c == ">") and not s.startswith("(", i + 1):
                self.i = i
                add(self._redirect("", _REDIR_OPS))
                continue
            # A word.
            w = self._word("n")
            j = self.i
            if (
                j < n and s[j] in "<>" and not s.startswith("(", j + 1)
                and w.plain() and _RE_FD_PREFIX.fullmatch(w.kw)
            ):
                add(self._redirect(w.kw, _REDIR_OPS, w.start))
                continue
            kw = w.kw
            if closed and kw not in _AFTER_CLOSE_WORDS:
                raise _Unsupported("word after compound command")
            if kw is not None and (closed or self._cmdpos(cur)):
                if kw in _STRIP_WORDS:
                    closed = False
                    continue
                if kw == "{":
                    self._enter()
                    braces += 1
                    closed = False
                    continue
                if kw == "}":
                    if not braces:
                        raise _Unsupported("unmatched }")
                    finish()
                    braces -= 1
                    self.depth -= 1
                    closed = True
                    continue
                if kw in ("fi", "done"):
                    finish()
                    closed = True
                    continue
                if kw == "esac":
                    if closer != "case" or parens or braces:
                        raise _Unsupported("unmatched esac")
                    finish()
                    self.term = "esac"
                    return units
                if not closed:
                    if kw == "case":
                        units.extend(self._case(cur, cur_sep))
                        cur = []
                        closed = True
                        continue
                    if kw in ("for", "select"):
                        self._for()
                        continue
                    if kw == "function":
                        self._function()
                        continue
                    if kw == "coproc":
                        self._blanks()
                        m = _RE_COPROC_NAME.match(s, self.i)
                        if m:
                            self.i = m.end()
                        continue
                    if kw == "repeat":
                        self._blanks()
                        if self.i >= n or s[self.i] in "\n;&|()<>":
                            raise _Unsupported("repeat")
                        self._word("n")
                        continue
                    if kw == "[[":
                        add(("w", self._cond(w.start)))
                        closed = True
                        continue
            add(("w", w))

    def _cmdpos(self, cur):
        """Command position: no word yet, or only a `time [-p] [--]` prefix
        (kept in the unit, INV-05; the compound after it still parses)."""
        if not cur:
            return True
        if cur[0][0] != "w" or cur[0][1].kw != "time":
            return False
        rest = [it[1].kw for it in cur[1:] if it[0] == "w"]
        return len(rest) == len(cur) - 1 and rest in ([], ["-p"], ["--"], ["-p", "--"])

    def _case(self, cur, cur_sep):
        s, n = self.s, self.n
        self._enter()
        self._blanks()
        if self.i >= n or s[self.i] in "\n;&|()<>":
            raise _Unsupported("case word")
        self._word("n")
        self._blanks_nl()
        w = self._word("n") if self.i < n and s[self.i] not in "\n;&|()<>" else None
        if w is None or w.kw != "in":
            raise _Unsupported("case without in")
        units = []
        saved_term = self.term
        while True:
            self._blanks_nl()
            if self.i >= n:
                raise _Unsupported("unterminated case")
            m = _RE_ESAC.match(s, self.i)
            if m:
                self.i = m.end()
                break
            if s[self.i] == "(":
                self.i += 1
            while True:
                self._blanks()
                if self.i >= n or s[self.i] in "\n;&|()<>":
                    raise _Unsupported("case pattern")
                self._word("n")
                self._blanks()
                if self.i < n and s[self.i] == "|":
                    self.i += 1
                    continue
                if self.i < n and s[self.i] == ")":
                    self.i += 1
                    break
                raise _Unsupported("case pattern")
            self.sep = None
            self.term = None
            units.extend(self.parse_list("case"))
            if self.term == "esac":
                break
        self.term = saved_term
        self.depth -= 1
        return units

    def _for(self):
        s, n = self.s, self.n
        self._blanks()
        if s.startswith("((", self.i):
            if self._arith(self.i, dollar=False, alt=False) is None:
                raise _Unsupported("for (( ))")
            return
        if self.i >= n or s[self.i] in "\n;&|()<>":
            raise _Unsupported("for name")
        self._word("n")
        self._blanks_nl()
        if self.i < n and s[self.i] not in "\n;&|()<>":
            save = self.i
            w = self._word("n")
            if w.kw != "in":
                if w.kw == "do":
                    self.i = save
                    return
                raise _Unsupported("for header")
            # The words after `in` are arguments, not commands; their
            # substitutions are still collected by the word lexer.
            while True:
                self._blanks()
                if self.i >= n or s[self.i] in "\n;":
                    return
                if s[self.i] in "&|()<>":
                    raise _Unsupported("for words")
                self._word("n")
        if self.i < n and s[self.i] == "(":
            raise _Unsupported("zsh for short form")

    def _function(self):
        s, n = self.s, self.n
        self._blanks()
        if self.i < n and s[self.i] not in "{(\n;&|<>":
            self._word("n")
            self._blanks()
        if self.i < n and s[self.i] == "(":
            j = self.i + 1
            while j < n and s[j] in " \t":
                j += 1
            if j >= n or s[j] != ")":
                raise _Unsupported("function parens")
            self.i = j + 1
        self._blanks_nl()

    def _cond(self, start):
        """`[[ ... ]]` as one unit word; `|`/`<`/`&&` inside are not shell
        operators; newlines are blanks (zsh reading)."""
        s, n = self.s, self.n
        parts = ["[["]
        while True:
            self._blanks()
            if self.i >= n:
                raise _Unsupported("unterminated [[")
            c = s[self.i]
            if c == "\n":
                if self.pending:
                    raise _Unsupported("newline in [[ with heredoc")
                self.i += 1
                continue
            if c == ";" or c == "#":
                raise _Unsupported("; in [[")
            if s.startswith("&&", self.i) or s.startswith("||", self.i):
                parts.append(s[self.i:self.i + 2])
                self.i += 2
                continue
            if c in "()":
                parts.append(c)
                self.i += 1
                continue
            if c in "<>":
                if s.startswith("(", self.i + 1):
                    raise _Unsupported("process substitution in [[")
                parts.append(c)
                self.i += 1
                continue
            w = self._word("c")
            if w.kw == "]]":
                break
            parts.append(_render(w.pieces))
        parts.append("]]")
        text = " ".join(parts)
        return _Word([_lit(text)], text, start, False)

    # -- redirections and heredocs -------------------------------------

    def _redirect(self, prefix, ops, op_pos=None):
        s, n = self.s, self.n
        if op_pos is None:
            op_pos = self.i
        for op in ops:
            if s.startswith(op, self.i):
                break
        else:
            raise _Unsupported("redirection")
        self.i += len(op)
        self._blanks()
        if self.i >= n:
            raise _Unsupported("redirection target")
        c = s[self.i]
        if c in "\n;&|()" or (c in "<>" and not s.startswith("(", self.i + 1)):
            raise _Unsupported("redirection target")
        w = self._word("n")
        if op in ("<<", "<<-"):
            quoted = any(p[3] for p in w.pieces)
            self.pending.append((_value(w.pieces), quoted, op == "<<-"))
        return ("r", prefix + op, w, op_pos)

    def _heredocs(self):
        """Called right after a newline token: read this list's pending
        heredoc bodies. A newline inside a substitution body does not start
        the bodies of heredocs opened before the substitution (bash and zsh
        read them after the newline that follows it)."""
        if not self.pending:
            return
        s, n = self.s, self.n
        pending, self.pending = self.pending, []
        for delim, quoted, strip in pending:
            body_start = self.i
            while True:
                j = s.find("\n", self.i)
                line = s[self.i:] if j < 0 else s[self.i:j]
                if (line.lstrip("\t") if strip else line) == delim:
                    body_end = self.i
                    self.i = n if j < 0 else j + 1
                    break
                if j < 0:
                    raise _Unsupported("unterminated heredoc")
                stripped = line.strip().replace("\\", "")
                if stripped:
                    self.ctx.heredoc_lines.add(stripped)
                self.i = j + 1
            if not quoted and body_end > body_start:
                body = s[body_start:body_end]
                if "$" in body or "`" in body:
                    p = _Parser(body, self.ctx, self.base + body_start, self.depth + 1, self.in_sub)
                    p._scan_expansions()

    def _scan_expansions(self):
        """Heredoc body with an unquoted delimiter: only `\\`, `$` and
        backtick are special; quotes are literal."""
        s, n = self.s, self.n
        while self.i < n:
            c = s[self.i]
            if c == "\\":
                self.i += 2
            elif c == "$":
                self._dollar(dq=True)
            elif c == "`":
                self._backtick(dq=False)
            else:
                self.i += 1

    def _comment(self):
        s, n, i = self.s, self.n, self.i
        j = s.find("\n", i)
        end = n if j < 0 else j
        self.i = end
        if self.in_sub:
            return
        text = s[i:end]
        if "$(" not in text and "`" not in text:
            return
        # Decision (e): the comment stays in the caller's line-based path;
        # only its substitutions are added, each tried on its own.
        k = 0
        while k < len(text):
            if text.startswith("$(", k) or text[k] == "`":
                ctx = _Ctx(self.ctx.no_alt)
                p = _Parser(text, ctx, self.base + i, self.depth, 0)
                p.i = k
                try:
                    if text[k] == "$":
                        p._dollar(dq=False)
                    else:
                        p._backtick(dq=False)
                except _Unsupported:
                    k += 1
                    continue
                self.ctx.nested.extend(ctx.nested)
                self.ctx.heredoc_lines |= ctx.heredoc_lines
                k = p.i
                continue
            k += 1

    # -- words ---------------------------------------------------------

    def _word(self, mode):
        s, n = self.s, self.n
        start = self.i
        self.ctx.steps += 1
        pieces = []
        run_re = _RE_LIT_RUN if mode == "n" else _RE_COND_RUN
        while self.i < n:
            i = self.i
            m = run_re.match(s, i)
            if m:
                pieces.append(_lit(m.group()))
                self.i = m.end()
                continue
            c = s[i]
            if c == "'":
                end = s.find("'", i + 1)
                if end < 0:
                    raise _Unsupported("unterminated '")
                val = s[i + 1:end]
                pieces.append(("L", "'" + val.translate(_NL_TO_SPACE) + "'", val, True, False))
                self.i = end + 1
            elif c == '"':
                pieces.append(self._dq())
            elif c == "\\":
                if i + 1 >= n:
                    raise _Unsupported("trailing backslash")
                nx = s[i + 1]
                if nx != "\n":
                    pieces.append(("L", "\\" + nx.translate(_NL_TO_SPACE), nx, True, False))
                self.i = i + 2
            elif c == "$":
                pieces.append(self._dollar(dq=False))
            elif c == "`":
                pieces.append(self._backtick(dq=False))
            elif c in "<>" and mode == "n" and s.startswith("(", i + 1):
                pieces.append(self._subst(i, i + 2, "procsubst", c + "("))
            elif c == "(" and mode == "n":
                so_far = s[start:i]
                if so_far == "=" and pieces and pieces[0][0] == "L" and not pieces[0][3]:
                    # zsh `=(...)` process substitution (a syntax error in bash).
                    pieces = [self._subst(i - 1, i + 1, "procsubst", "=(")]
                elif _RE_ARRAY_PREFIX.fullmatch(so_far) and all(p[0] == "L" and not p[3] for p in pieces):
                    pieces.append(self._array())
                else:
                    # `name()` function definition; parse_list rejects
                    # every other `(` after a word (glob qualifiers, extglob).
                    break
            elif mode == "c" and c in "&|" and not s.startswith(c + c, i):
                pieces.append(_lit(c))
                self.i = i + 1
            else:
                break
        if self.i == start:
            raise _Unsupported("empty word")
        return _Word(pieces, s[start:self.i], start)

    def _array(self):
        """`name=(...)`: array elements are words, not commands."""
        s, n = self.s, self.n
        self.i += 1
        parts = []
        while True:
            self._blanks_nl()
            if self.i >= n:
                raise _Unsupported("unterminated array")
            c = s[self.i]
            if c == ")":
                self.i += 1
                break
            if c in ";&|(<>":
                raise _Unsupported("array element")
            parts.append(_render(self._word("n").pieces))
        text = "(" + " ".join(parts) + ")"
        return ("L", text, text, True, False)

    def _dq(self):
        s, n = self.s, self.n
        i = self.i + 1
        render = ['"']
        value = []
        has_x = False
        while True:
            if i >= n:
                raise _Unsupported('unterminated "')
            m = _RE_DQ_RUN.match(s, i)
            if m:
                t = m.group()
                render.append(t.translate(_NL_TO_SPACE))
                value.append(t)
                i = m.end()
                continue
            c = s[i]
            if c == '"':
                i += 1
                break
            if c == "\\":
                if i + 1 >= n:
                    raise _Unsupported('unterminated "')
                nx = s[i + 1]
                if nx == "\n":
                    i += 2
                elif nx in '$`"\\':
                    render.append("\\" + nx)
                    value.append(nx)
                    i += 2
                else:
                    render.append("\\")
                    value.append("\\")
                    i += 1
                continue
            self.i = i
            p = self._dollar(dq=True) if c == "$" else self._backtick(dq=True)
            i = self.i
            if p[0] == "X":
                has_x = True
            render.append(p[1])
            value.append(p[2])
        self.i = i
        render.append('"')
        return ("X" if has_x else "L", "".join(render), "".join(value), True, False)

    def _dollar(self, dq):
        s, n = self.s, self.n
        i = self.i
        nx = s[i + 1] if i + 1 < n else ""
        if nx == "\\" and s.startswith("\n", i + 2):
            # bash joins `$\<newline>(` into `$(`; zsh does not inside "...".
            raise _Unsupported("line continuation after $")
        if nx == "(":
            if s.startswith("((", i + 1):
                arith = self._arith(i, dollar=True)
                if arith is not None:
                    return ("X", arith, s[i:self.i], False, False)
            return self._subst(i, i + 2, "subst", "$(")
        if nx == "{":
            return self._param(i, dq)
        m = _RE_NAME.match(s, i + 1) if nx else None
        if m:
            self.i = m.end()
            t = s[i:self.i]
            return ("X", t, t, False, False)
        if nx and (nx in "0123456789@*#?$!-"):
            self.i = i + 2
            t = s[i:i + 2]
            return ("X", t, t, False, False)
        if not dq and nx == "'":
            return self._ansi(i)
        if not dq and nx == '"':
            self.i = i + 1
            p = self._dq()
            return (p[0], p[1], p[2], True, True)
        self.i = i + 1
        return _lit("$")

    def _subst(self, i, body_start, kind, prefix):
        """`$(`, `<(`, `>(`, `=(`: the body is parsed in place as commands
        up to the matching ')'."""
        s = self.s
        self._enter()
        saved = (self.pending, self.sep, self.term)
        self.pending = []
        self.sep = None
        self.in_sub += 1
        self.i = body_start
        self.parse_list(")")
        self.in_sub -= 1
        self.pending, self.sep, self.term = saved
        self.depth -= 1
        end = self.i
        body = s[body_start:end - 1]
        self._add_nested(body, kind, i)
        raw = s[i:end]
        render = prefix + ":)" if _RE_QUOTY.search(body) else raw
        return ("X", render, raw, False, False)

    def _backtick(self, dq):
        s, n = self.s, self.n
        i = self.i
        j = i + 1
        buf = []
        while True:
            if j >= n:
                raise _Unsupported("unterminated `")
            c = s[j]
            if c == "`":
                break
            if c == "\\" and j + 1 < n and (s[j + 1] in "`\\$" or (dq and s[j + 1] == '"')):
                buf.append(s[j + 1])
                j += 2
                continue
            buf.append(c)
            j += 1
        self.i = j + 1
        body = "".join(buf)
        self._enter()
        p = _Parser(body, self.ctx, self.base + i + 1, self.depth, self.in_sub + 1)
        p.parse_list(None)
        self.depth -= 1
        self._add_nested(body, "backtick", i)
        raw = s[i:j + 1]
        render = "`:`" if _RE_QUOTY.search(raw[1:-1]) else raw
        return ("X", render, raw, False, False)

    def _param(self, i, dq):
        """`${...}`: balanced braces; quotes and expansions inside."""
        s, n = self.s, self.n
        self._enter()
        self.i = i + 2
        level = 0
        while True:
            if self.i >= n:
                raise _Unsupported("unterminated ${")
            m = _RE_PARAM_RUN.match(s, self.i)
            if m:
                self.i = m.end()
                continue
            c = s[self.i]
            if c == "}":
                self.i += 1
                if level == 0:
                    break
                level -= 1
            elif c == "{":
                level += 1
                self.i += 1
            elif c == "'":
                if dq:
                    self.i += 1
                else:
                    end = s.find("'", self.i + 1)
                    if end < 0:
                        raise _Unsupported("unterminated '")
                    self.i = end + 1
            elif c == '"':
                self._dq()
            elif c == "\\":
                if self.i + 1 >= n:
                    raise _Unsupported("unterminated ${")
                self.i += 2
            elif c == "$":
                self._dollar(dq)
            else:
                self._backtick(dq)
        self.depth -= 1
        raw = s[i:self.i]
        if _RE_QUOTY.search(raw):
            # Neutralised without quotes/backslash/newlines, but the parameter
            # name stays: raw-text checks (secret variable names) still see it.
            render = "${" + _RE_PARAM_NAME.match(raw, 2).group() + ":}"
        else:
            render = raw
        return ("X", render, raw, False, False)

    def _ansi(self, i):
        """`$'...'` (ANSI-C quoting); an unknown escape is unsupported."""
        s, n = self.s, self.n
        j = i + 2
        out = []
        while True:
            if j >= n:
                raise _Unsupported("unterminated $'")
            m = _RE_ANSI_RUN.match(s, j)
            if m:
                out.append(m.group())
                j = m.end()
                continue
            if s[j] == "'":
                break
            if j + 1 >= n:
                raise _Unsupported("unterminated $'")
            e = s[j + 1]
            if e in _ANSI_SIMPLE:
                out.append(_ANSI_SIMPLE[e])
                j += 2
                continue
            if e in "01234567":
                m = _RE_OCTAL.match(s, j + 1)
                out.append(chr(int(m.group(), 8) & 0xFF))
                j = m.end()
                continue
            if e in _RE_HEX:
                m = _RE_HEX[e].match(s, j + 2)
                if not m or int(m.group(), 16) > 0x10FFFF:
                    raise _Unsupported("bad $' escape")
                out.append(chr(int(m.group(), 16)))
                j = m.end()
                continue
            if e == "c" and j + 2 < n and s[j + 2] != "'":
                out.append(chr(ord(s[j + 2]) & 0x1F))
                j += 3
                continue
            raise _Unsupported("unknown $' escape")
        self.i = j + 1
        # bash ends the string at a NUL byte.
        val = "".join(out).split("\x00", 1)[0]
        return ("L", shlex.quote(val.translate(_NL_TO_SPACE)), val, True, False)

    def _arith(self, i, dollar, alt=True):
        """`$((...))` / `((...))`. Returns the unit render, or None when the
        text is not arithmetic (the first unmatched ')' is not followed by
        ')'): the caller then reads it as `$( (...) )` / `( (...) )`. When
        it is arithmetic, the alternative command reading is added as
        nested `arith_alt` if it parses."""
        s, n = self.s, self.n
        saved = (self.i, self.depth, len(self.ctx.nested))
        self._enter()
        self.i = i + (3 if dollar else 2)
        level = 0
        render = []
        while True:
            if self.i >= n:
                raise _Unsupported("unterminated arithmetic")
            m = _RE_ARITH_RUN.match(s, self.i)
            if m:
                render.append(m.group().translate(_NL_TO_SPACE))
                self.i = m.end()
                continue
            c = s[self.i]
            if c == "(":
                level += 1
                render.append(c)
                self.i += 1
            elif c == ")":
                if level == 0:
                    if s.startswith("))", self.i):
                        self.i += 2
                        break
                    self.ctx.steps += self.i - i
                    self.i, self.depth = saved[0], saved[1]
                    del self.ctx.nested[saved[2]:]
                    return None
                level -= 1
                render.append(c)
                self.i += 1
            elif c == "\n":
                if self.pending:
                    raise _Unsupported("newline in arithmetic with heredoc")
                render.append(" ")
                self.i += 1
            elif c == "'":
                end = s.find("'", self.i + 1)
                if end < 0:
                    raise _Unsupported("unterminated '")
                render.append("'" + s[self.i + 1:end].translate(_NL_TO_SPACE) + "'")
                self.i = end + 1
            elif c == '"':
                render.append(self._dq()[1])
            elif c == "\\":
                if self.i + 1 >= n:
                    raise _Unsupported("trailing backslash")
                nx = s[self.i + 1]
                if nx != "\n":
                    render.append("\\" + nx.translate(_NL_TO_SPACE))
                self.i += 2
            elif c == "$":
                render.append(self._dollar(dq=False)[1])
            else:
                render.append(self._backtick(dq=False)[1])
        self.depth -= 1
        end = self.i
        self.ctx.steps += end - i
        if alt and self.in_sub == 0 and not self.ctx.no_alt:
            alt_text = s[i + (2 if dollar else 1):end - 1]
            try:
                _Parser(alt_text, _Ctx(no_alt=True), 0, self.depth + 1, 1).parse_list(None)
            except _Unsupported:
                pass
            else:
                self._add_nested(alt_text, "arith_alt", i)
        return ("$((" if dollar else "((") + "".join(render) + "))"

    # -- unit records --------------------------------------------------

    def _build(self, cur, sep):
        """Unit records for one simple command: the original, then its
        dialect variants (INV-11)."""
        words = [it[1] for it in cur if it[0] == "w"]
        pos = self.base + (cur[0][1].start if cur[0][0] == "w" else cur[0][3])
        for it in cur:
            if it[0] == "r" and it[1].endswith("<<<"):
                tokens = [_value(w.pieces) for w in words]
                rest = _unwrap_tokens(tokens)
                if rest and rest[0].rsplit("/", 1)[-1] in _SHELLS:
                    self._add_nested(_value(it[2].pieces), "herestring_shell", it[3])
        multiline = tuple(
            v for v in (_value(w.pieces) for w in words) if _RE_BODY_CHARS.search(v)
        )
        raws = [w.raw for w in words]
        text, dyn = _assemble(cur, raws, ())
        records = [(text, pos, sep, dyn, multiline, None)]
        present = set()
        for w in words:
            if w.variants_ok:
                present |= _word_features(w.pieces)
        # One reading per non-empty set of dialect features, each feature
        # applied to every word that has it (bash: braces expanded and the
        # `$` of `$"` dropped; zsh: `=` dropped and the `$` literal).
        feats = [f for f in _FEATURES if f in present]
        readings = [
            frozenset(c) for k in range(1, len(feats) + 1)
            for c in itertools.combinations(feats, k)
        ]
        self.ctx.variants += len(readings)
        if self.ctx.variants > _MAX_VARIANTS:
            raise _Unsupported("too many variants")
        seen = {text}
        for reading in readings:
            text, dyn = _assemble(cur, raws, reading)
            if text not in seen:
                seen.add(text)
                records.append((text, pos, sep, dyn, multiline, True))
        return records


def _assemble(cur, raws, reading):
    """(unit text, dyn_head) of one simple command under a dialect reading
    (empty reading = the original words)."""
    parts = []
    word_list = []
    raw_iter = iter(raws)
    for it in cur:
        if it[0] != "w":
            parts.append(it[1] + " " + _render(it[2].pieces))
            continue
        raw = next(raw_iter)
        if not reading or not it[1].variants_ok:
            parts.append(_render(it[1].pieces))
            word_list.append((it[1].pieces, raw))
            continue
        for pieces in _word_reading(it[1].pieces, reading):
            parts.append(_render(pieces))
            word_list.append((pieces, _render(pieces)))
    return " ".join(parts), _dyn_head(word_list)


def _dyn_head(words):
    """The command word (first word that is not an assignment, a wrapper
    from common._WRAPPER_COMMANDS or a wrapper option) holds an unquoted
    or double-quoted expansion (INV-09)."""
    i, n = 0, len(words)
    while i < n:
        pieces, raw = words[i]
        if _RE_ASSIGN.match(raw):
            i += 1
            continue
        if _is_literal(pieces):
            base = _value(pieces).rsplit("/", 1)[-1]
            if base in _WRAPPER_COMMANDS:
                value_opts = _WRAPPER_VALUE_OPTIONS.get(base, ())
                duration = base == "timeout"  # its first positional operand
                i += 1
                while i < n:
                    t = _value(words[i][0])
                    if t.startswith("-"):
                        if base == "command" and t in ("-v", "-V"):
                            return False  # prints, runs nothing
                        i += 2 if t in value_opts else 1
                    elif "=" in t or t.isdigit() or _RE_DURATION.match(t):
                        duration = False
                        i += 1
                    elif duration:
                        duration = False
                        i += 1
                    else:
                        break
                continue
            return False
        return any(p[0] == "X" for p in pieces)
    return False


def _has_eq(pieces):
    first = pieces[0]
    return first[0] == "L" and not first[3] and _RE_EQ_CMD.match(first[1]) is not None


def _word_features(pieces):
    """Dialect features of one word (INV-11)."""
    feats = set()
    if _has_eq(pieces):
        feats.add("eq")
    if any(p[4] for p in pieces):
        feats.add("dollar")
    if _brace_expand(pieces) is not None:
        feats.add("brace")
    return feats


def _word_reading(pieces, reading):
    """The words one word becomes under a dialect reading (INV-11)."""
    if "eq" in reading and _has_eq(pieces):
        pieces = [_lit(pieces[0][1][1:])] + pieces[1:]
    if "dollar" in reading:
        pieces = [(p[0], "'$'" + p[1], "$" + p[2], True, False) if p[4] else p for p in pieces]
    if "brace" in reading:
        expanded = _brace_expand(pieces)
        if expanded is not None:
            return expanded
    return [pieces]


def _brace_expand(pieces):
    """bash brace expansion of the unquoted `{a,b}` / `{x..y[..z]}` parts
    of a word; None when nothing expands."""
    if not any(p[0] == "L" and not p[3] and "{" in p[1] for p in pieces):
        return None
    if len(pieces) == 1:
        # The common shape, one flat `{a,b,...}` group in a plain word.
        m = _RE_SIMPLE_BRACE.fullmatch(pieces[0][1])
        if m:
            alts = m.group(2).split(",")
            if len(alts) > _MAX_VARIANTS:
                raise _Unsupported("brace expansion too large")
            texts = [m.group(1) + a + m.group(3) for a in alts]
            return [[_lit(t)] for t in texts if t]
    atoms = []
    for p in pieces:
        if p[0] == "L" and not p[3]:
            atoms.extend(p[1])
        else:
            atoms.append(p)
    opens = atoms.count("{")
    if opens == 0:
        return None
    # Every group multiplies or adds results, so more groups than the
    # variant cap cannot stay within it; refuse before the recursive scan
    # (which re-reads the word once per group).
    if opens > _MAX_VARIANTS:
        raise _Unsupported("brace expansion too large")
    results = _bx(atoms)
    if len(results) <= 1:
        return None
    words = []
    for atom_list in results:
        word, run = [], []
        for a in atom_list:
            if isinstance(a, str):
                run.append(a)
                continue
            if run:
                word.append(_lit("".join(run)))
                run = []
            word.append(a)
        if run:
            word.append(_lit("".join(run)))
        if word:
            words.append(word)
    return words


def _bx(atoms):
    # One linear pass pairs each "{" with its "}" and its top-level commas
    # (a per-"{" forward scan is quadratic on inputs like "{{{{...").
    stack, match = [], {}
    for j, a in enumerate(atoms):
        if a == "{":
            stack.append((j, []))
        elif a == "}" and stack:
            k, commas = stack.pop()
            match[k] = (j, commas)
        elif a == "," and stack:
            stack[-1][1].append(j)
    for k in sorted(match):
        end, commas = match[k]
        if commas:
            bounds = [k] + commas + [end]
            alts = [atoms[bounds[x] + 1:bounds[x + 1]] for x in range(len(bounds) - 1)]
        else:
            inner = atoms[k + 1:end]
            if not all(isinstance(x, str) for x in inner):
                continue
            seq = _sequence("".join(inner))
            if seq is None:
                continue
            alts = [list(x) for x in seq]
        results = []
        for alt in alts:
            results.extend(_bx(atoms[:k] + alt + atoms[end + 1:]))
            if len(results) > _MAX_VARIANTS:
                raise _Unsupported("brace expansion too large")
        return results
    return [atoms]


def _sequence(text):
    m = _RE_SEQ.fullmatch(text)
    if not m:
        return None
    if m.group(1) is not None:
        a, b = int(m.group(1)), int(m.group(2))
        step = abs(int(m.group(3) or 1)) or 1
        if abs(b - a) // step + 1 > _MAX_VARIANTS:
            raise _Unsupported("sequence too large")
        rng = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        return [str(x) for x in rng]
    a, b = ord(m.group(4)), ord(m.group(5))
    step = abs(int(m.group(6) or 1)) or 1
    if abs(b - a) // step + 1 > _MAX_VARIANTS:
        raise _Unsupported("sequence too large")
    rng = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
    return [chr(x) for x in rng]


# Fast path: one simple command made only of plain words and whole
# single/double-quoted literal words (no expansion, escape, operator,
# redirection, comment, brace or newline-like character, no word starting
# with `=`). Such a line is one unit with no nested text, no heredoc and no
# dialect variant; the general parser would produce exactly this record.
_NLX = "\r\x0b\x0c\x85  "
_FAST_PLAIN = "[^ \\t\\n;&|()<>'\"\\\\$`#{" + _NLX + "]"
_FAST_WORD = (
    "(?:(?!=)" + _FAST_PLAIN + "+|'[^'\\n" + _NLX + "]*'|\"[^\"\\\\$`\\n" + _NLX + "]*\")"
)
_RE_FAST_LINE = re.compile("[ \\t]*(" + _FAST_WORD + "(?:[ \\t]+" + _FAST_WORD + ")*)[ \\t]*")
_RE_FAST_WORD = re.compile(_FAST_WORD)


def _parse_simple(text):
    """ParsedCommand for the fast-path shape, or None when the text does
    not have it."""
    m = _RE_FAST_LINE.fullmatch(text)
    if m is None:
        return None
    words = _RE_FAST_WORD.findall(m.group(1))
    if words[0] in _RESERVED:
        return None
    bodies = ()
    for i, w in enumerate(words):
        c = w[0]
        if c == "'" or c == '"':
            value = w[1:-1]
            if _RE_BODY_CHARS.search(value):
                bodies += (value,)
            quoted = shlex.quote(value)
            words[i] = "'" + value + "'" if quoted in _RESERVED else quoted
    joined = " ".join(words)
    return ParsedCommand([Unit(joined, m.start(1), None, None, False, bodies)], [], frozenset(), joined)


def parse_command(text):
    """ParsedCommand for a shell command string, or None when the text is
    not a str or holds a construct outside the closed grammar. Never
    raises."""
    try:
        if not isinstance(text, str) or _RE_BAD_CTRL.search(text):
            return None
        fast = _parse_simple(text)
        if fast is not None:
            return fast
        ctx = _Ctx()
        records = _Parser(text, ctx).parse_list(None)
        units = []
        canonical = []
        origin = None
        for t, pos, sep, dyn, multiline, is_variant in records:
            if is_variant:
                units.append(Unit(t, pos, sep, origin, dyn, multiline))
                continue
            origin = len(units)
            units.append(Unit(t, pos, sep, None, dyn, multiline))
            if canonical:
                canonical.append(";" if sep in (None, "\n") else sep)
            canonical.append(t)
        nested = sorted(ctx.nested, key=lambda nd: nd.pos)
        return ParsedCommand(units, nested, frozenset(ctx.heredoc_lines), " ".join(canonical))
    except Exception:
        return None


def extract_substitutions(text):
    """Bodies of every `$(...)`, backtick, `<(...)` and `>(...)` found by a
    plain quote-aware scan (for the caller's fallback when parse_command
    returns None), or None when they do not balance or a quote is left
    open. Never raises."""
    try:
        if not isinstance(text, str):
            return None
        found = []
        # Each frame: [kind, body_start, paren_level]; kind "top", "sub"
        # (`$(`/`<(`/`>(`) or "dq".
        stack = [["top", 0, 0]]
        i, n = 0, len(text)
        while i < n:
            c = text[i]
            frame = stack[-1]
            kind = frame[0]
            if c == "\\":
                i += 2
                continue
            if kind == "dq":
                if c == '"':
                    stack.pop()
                    i += 1
                    continue
            else:
                if c == "'":
                    end = text.find("'", i + 1)
                    if end < 0:
                        return None
                    i = end + 1
                    continue
                if c == '"':
                    stack.append(["dq", i, 0])
                    i += 1
                    continue
                if c in "<>" and text.startswith("(", i + 1):
                    stack.append(["sub", i + 2, 0])
                    i += 2
                    continue
                if kind == "sub":
                    if c == "(":
                        frame[2] += 1
                    elif c == ")":
                        if frame[2] == 0:
                            found.append((frame[1], text[frame[1]:i]))
                            stack.pop()
                            i += 1
                            continue
                        frame[2] -= 1
            if c == "$" and text.startswith("(", i + 1):
                stack.append(["sub", i + 2, 0])
                i += 2
                continue
            if c == "`":
                j = i + 1
                while j < n and text[j] != "`":
                    j += 2 if text[j] == "\\" else 1
                if j >= n:
                    return None
                # The shell runs the de-escaped body (nested backticks).
                esc = r'\\([`\\$"])' if kind == "dq" else r"\\([`\\$])"
                found.append((i + 1, re.sub(esc, r"\1", text[i + 1:j])))
                i = j + 1
                continue
            i += 1
        if len(stack) != 1:
            return None
        return [body for _, body in sorted(found)]
    except Exception:
        return None
