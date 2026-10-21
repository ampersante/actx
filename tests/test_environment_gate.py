"""TK-71: the gate refuses commands that print the process environment.

One data table per verdict; every row becomes a subtest. Denied rows are
also run through the hook (Claude and Codex policies): a denied command must
come back as a deny without any rewrite.
"""

import json
import unittest

from actx_lib import hook, security_gate

T1 = "T1_CREDENTIAL_ACCESS"

DENY = (
    # printenv / env
    "printenv",
    "printenv -0",
    "printenv SYNTHETIC_API_KEY",
    "printenv HOME SYNTHETIC_TOKEN",
    "/usr/bin/printenv SYNTHETIC_PASSWORD",
    "command printenv SYNTHETIC_AUTH_TOKEN",
    "actx run printenv SYNTHETIC_TOKEN",
    "bash -c 'printenv SYNTHETIC_API_KEY'",
    "env",
    "env -u REMOVE_ME",
    "env --unset REMOVE_ME",
    "env -C /synthetic/work",
    "env -u REMOVE_ME -i",
    # shell builtins that print variables
    "set",
    "export",
    "export -p",
    "export -p --",
    "command export -p",
    "declare -px",
    "declare -x",
    "typeset -p",
    "typeset -xp",
    "readonly -p",
    "typeset -g",
    "typeset -r",
    "typeset -m 'SYNTHETIC_*TOKEN*'",
    "declare -p SYNTHETIC_PASSWORD",
    # ps
    "ps eww",
    "ps auxe",
    "ps axe",
    "/bin/ps auxeww",
    "ps -Eww",
    "ps -AEww",
    "ps --format environ",
    "ps -opid -E",
    # /proc/<pid>/environ through readers and spellings
    "cat /proc/self/environ",
    "actx cat /proc/self/environ",
    "head -c 64 /proc/123/environ",
    "grep -a X /proc/self/environ",
    "tr '\\0' '\\n' < /proc/123/environ",
    "cat</proc/self/environ",
    "od -c /proc/thread-self/environ",
    "xxd /proc/$$/environ",
    "strings /proc/42/environ",
    "cat /proc/self/task/123/environ",
    "cat /proc/self/root/proc/self/environ",
    "cat /proc/self/../self/environ",
    "cat /proc/self/environ*",
    "cat /proc/self/*nviron",
    "cat /proc/self/[e]nviron",
    "echo $(cat /proc/self/environ)",
    # inline interpreter code
    "python3 -c 'print(open(\"/proc/self/environ\").read())'",
    "python3 -c 'import os; print(vars(os))'",
    "python3 -c 'import os as o; print(o.__dict__)'",
    "python3 -c 'import os; print(globals()[\"os\"].__dict__)'",
    "python3 -c 'from os import environ as e; print(e)'",
    "python3 -c 'import os; print(os.environb)'",
    "python3 -c 'import os; print(os.getenv(\"SYNTHETIC_API_KEY\"))'",
    "node -p 'process.env'",
    "node -pe 'process.env'",
    "node -e 'console.log(process[\"env\"])'",
    "bun -p 'process.env'",
    "deno eval 'console.log(Deno.env.toObject())'",
    "ruby -e 'p ENV'",
    "ruby -ne 'p ENV'",
    "perl -E 'say %ENV'",
    "perl -le 'print %ENV'",
    "php -r 'print_r(getenv());'",
    # redirection suffixes are not operands
    "printenv 2>&1",
    "printenv > out.txt",
    "env 2>&1",
    "env > out.txt",
    "env -u REMOVE_ME 2>&1",
    "set 2>&1",
    "export -p 2>&1",
    "export -p > out.txt",
    "declare -px 2>/dev/null",
    "ps eww 2>&1",
    "ps -Eww > out.txt",
    "cat /proc/self/environ 2>&1",
    "export -p >> /tmp/x",
    "export -p >>/tmp/x",
    "env >> /tmp/x",
    "printenv >> /tmp/x",
    "set 2>> /tmp/x",
    "set <> /tmp/x",
    # flags before the inline code, per interpreter
    "python3 -E -c 'import os; print(os.environ)'",
    "python3 -I -c 'import os; print(os.environ)'",
    "python3 -BE -c 'import os; print(os.environ)'",
    "python3 -E -m code -c 'import os; print(os.environ)'",
    "ruby -E utf-8 -e 'p ENV'",
    "ruby -I lib -r json -e 'p ENV'",
    "perl -C -e 'print %ENV'",
    "perl -Mstrict -we 'print %ENV'",
    "php -f x.php -r 'print_r(getenv());'",
    "node -p -e 'process.env'",
    "node --stack-size 900 -p 'process.env'",
    "node --require x -p 'process.env'",
    "bun run -e 'process.env'",
    "bun --preload x -p 'process.env'",
    "lua -l x -e 'print(os.getenv(\"SYNTHETIC_API_KEY\"))'",
    # vendor-prefixed and auth names
    "printenv DATABASE_URL",
    "printenv GITHUB_PAT",
    "printenv SSH_AUTH_SOCK",
    "python3 -c 'import os; print(os.getenv(\"DATABASE_URL\"))'",
    # leading double slash before proc
    "cat //proc/self/environ",
    "cat //proc/self/task/1/environ",
    # attached eval forms, flags before the code
    "node --eval='console.log(process.env)'",
    "node --print='process.env'",
    "python3 -W ignore -c 'import os; print(os.environ)'",
    "python3 -u -c 'import os; print(os.environ)'",
    # BSD e modifier after other arguments, awk / jq program text
    "ps aux e",
    "ps -A e",
    "awk 'BEGIN{for (k in ENVIRON) print k}'",
    "jq -n '$ENV'",
    "jq -n env",
)

ALLOW = (
    "printenv PATH",
    "printenv HOME LANG",
    "env -u REMOVE_ME true",
    "env -C /synthetic/work true",
    "env -i true",
    "env SYNTHETIC_FLAG=1 true",
    "env -- true",
    "env -u REMOVE_ME python3 script.py",
    "set --",
    "set -e",
    "set -o pipefail",
    "set +o",
    "export PATH=/synthetic/bin",
    "export SYNTHETIC_FLAG",
    "export -n SYNTHETIC_FLAG",
    "declare -a items",
    "declare -p PATH",
    "typeset +x",
    "local value=1",
    "ps",
    "ps -ef",
    "ps aux",
    "ps -eo pid,comm",
    "ps -o pid,command",
    "ps -p 123 -o comm=",
    "ps -C perl",
    "cat /proc/self/status",
    "cat /proc/cpuinfo",
    "cat /tmp/proc/self/environ",
    "cat environ",
    "grep '/proc/self/environ' README.md",
    "echo '/proc/self/environ'",
    "python3 -c 'import os; print(globals())'",
    "python3 -c 'import os; print(os.getenv(\"PATH\"))'",
    "python3 -c 'print(1 + 1)'",
    "python3 -m pytest -k environment tests",
    "node -e 'console.log(1)'",
    "ruby -e 'puts 1'",
    "perl -e 'print 1'",
    "deno test",
    # script / module arguments are not inline code
    "python3 tools/build.py -profile ENV_prod",
    "python3 tools/build.py -file environment.txt",
    "python3 script.py -e environment",
    "python3 -m pytest -ve tests/test_environment.py",
    "node -r ./src/environ-setup.js app.js",
    "node ./tools/make.js -type ENV",
    "node app.js -e ENV_FILE",
    "node --test tests/environment.test.js",
    "ruby script.rb -e ENV",
    "perl script.pl -e ENV",
    "php -d memory_limit=1G script.php -r ENV",
    "deno run main.ts eval ENV",
    "deno eval 'console.log(1)'",
    "uv run python script.py -file environ.txt",
    # function listings are not variable listings
    "declare -f",
    "declare -F",
    "typeset -f",
    "export -f",
    # narrow credential name class and /proc listings
    "printenv AWS_REGION",
    "printenv GIT_AUTHOR_NAME",
    "ls /proc/*",
    "ls /proc/self/*",
    "cat /proc/net/*",
    "ps -u eli",
    "ps --user eli",
    "ps 2>&1",
    "set -- 2>&1",
    "export PATH=/synthetic/bin 2>&1",
    "jq . env.json",
    "awk '{print $1}' data.txt",
    # Word-only markers: ordinary inline code mentioning similar words.
    "python3 -c \"import json; print(json.load(open('environment.json'))['name'])\"",
    "python3 -c \"print('environment ok')\"",
    "python3 -c \"import sys; print(vars(sys.flags))\"",
    "node -e \"console.log(require('./config/ENV_defaults.json'))\"",
    "awk '/ENVIRONMENT/ {print $2}' deploy.log",
)

# Not denied by T1 (T5 asks for installs, which is unrelated to this task).
NOT_DENIED = (
    "python3 -m pip install -e ./environment-tools",
    "python3 -m pip install -r requirements/environment.txt",
)

# Allowed and rewritten by the hook (the rewrite is not a license to dump).
ALLOW_REWRITTEN = (
    "cat /proc/self/status",
    "grep '/proc/self/environ' README.md",
)


def _payload(command, turn_id=None):
    data = {"tool_name": "Bash", "tool_input": {"command": command}}
    if turn_id:
        data["turn_id"] = turn_id
    return json.dumps(data)


class EnvironmentGateTests(unittest.TestCase):
    def test_denied_commands(self):
        for command in DENY:
            with self.subTest(command=command):
                res = security_gate.evaluate_security(command)
                self.assertEqual((res.decision, res.category), ("deny", T1), res)

    def test_allowed_commands(self):
        for command in ALLOW:
            with self.subTest(command=command):
                res = security_gate.evaluate_security(command)
                self.assertEqual(res.decision, "allow", res)

    def test_script_arguments_are_not_denied(self):
        for command in NOT_DENIED:
            with self.subTest(command=command):
                res = security_gate.evaluate_security(command)
                self.assertNotEqual(res.decision, "deny", res)

    def test_hook_denies_without_rewrite(self):
        for agent, turn_id in (("claude", None), ("codex", "t1")):
            for command in DENY:
                with self.subTest(agent=agent, command=command):
                    out = hook.process(_payload(command, turn_id), agent=agent)
                    spec = out["hookSpecificOutput"]
                    self.assertEqual(spec["permissionDecision"], "deny")
                    self.assertIn(T1, spec["permissionDecisionReason"])
                    self.assertNotIn("updatedInput", spec)

    def test_hook_still_rewrites_safe_proc_reads(self):
        for command in ALLOW_REWRITTEN:
            with self.subTest(command=command):
                out = hook.process(_payload(command), agent="claude")
                spec = out["hookSpecificOutput"]
                self.assertEqual(spec["permissionDecision"], "allow")
                self.assertEqual(spec["updatedInput"]["command"], "actx " + command)


if __name__ == "__main__":
    unittest.main()
