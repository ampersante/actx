"""TK-59 STEP-R3(e) helper: executed in a subprocess by hook_contract_check.py
with sys.path[0] (via PYTHONPATH) pointing at either the base-revision
actx_lib snapshot or the current checkout. Reads the gate corpus + fixed
HOME from argv[1], evaluates actx_lib.hook.process() for both hook schemas
over every corpus command, and writes a JSON array of [schema, command,
result] to stdout. Stdlib only; never imported directly - always run as
`python3 tools/hook_contract_runner.py <fixture path>` by the parent check.
"""
import json
import os
import sys

fixture_path = sys.argv[1]

with open(fixture_path, encoding="utf-8") as f:
    fixture = json.load(f)

os.environ["HOME"] = fixture["home"]

import actx_lib.hook as hook  # noqa: E402  (actx_lib resolved via caller's PYTHONPATH)

commands = sorted(fixture["corpus"].keys())

out = []
for command in commands:
    claude_stdin = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    agy_stdin = json.dumps({"toolCall": {"name": "run_command", "args": {"CommandLine": command}}})
    claude_result = hook.process(claude_stdin)
    agy_result = hook.process(agy_stdin)
    out.append(["claude", command, claude_result])
    out.append(["antigravity", command, agy_result])

json.dump(out, sys.stdout, sort_keys=True)
