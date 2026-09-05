"""TK-40: kubectl + helm CLI families (wave 2, executor E2).

Unit matrices for the family records, effective_verbs, rewriter and hang
policy, plus subprocess E2E runs on shim executables (tmp dir, PATH
injection, no network) - the precedents are test_cli_families.py and
test_hook.py. The pre-migration verdicts live in
test_golden_kubectl_helm.py (physically frozen corpus, H-F10/N-F12a).
"""

import json
import os
import shlex
import sqlite3
import stat
import subprocess
import tempfile
import time
import unittest

from actx_lib import cli_families, hang_policy, rewriter, security_gate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")

BASE_CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}

NEVER_WRAP = "never_wrap"
DEFAULT = "default"

# Wave-1 adversarial pattern: a secret whose key AND value contain none of
# the redaction pattern words. never-wrap is the only thing keeping it out
# of tee/history (N-F3a: base64 secret values dodge pattern redaction).
KUBECTL_SECRET_LINE = "db-creds: cHJvZDpOWnRlN3h1QGhvc3QvZGI="


class EffectiveVerbsTests(unittest.TestCase):
    """cli_families.effective_verbs (N-F11/H-F11): the single skip-logic
    source consumed by rewriter, hang_policy and infra_filter."""

    def test_value_flag_skips_flag_and_value(self):
        self.assertEqual(
            cli_families.effective_verbs(["kubectl", "-n", "prod", "get", "pods"]),
            ["get", "pods"],
        )

    def test_all_value_flags_skip(self):
        for flag in ("-n", "--namespace", "--context", "--cluster",
                     "--kubeconfig"):
            with self.subTest(flag=flag):
                self.assertEqual(
                    cli_families.effective_verbs(
                        ["kubectl", flag, "x", "get", "pods"]
                    ),
                    ["get", "pods"],
                )

    def test_equals_form_skips_whole_token(self):
        self.assertEqual(
            cli_families.effective_verbs(
                ["kubectl", "--namespace=prod", "get", "pods"]
            ),
            ["get", "pods"],
        )

    def test_equals_form_value_cannot_fake_a_verb(self):
        # `--namespace=get` is one token: the value stays inside it, so the
        # effective verbs are ["pods"] - no "get" materializes (FP impossible).
        self.assertEqual(
            cli_families.effective_verbs(
                ["kubectl", "--namespace=get", "pods"]
            ),
            ["pods"],
        )

    def test_value_flag_eats_a_value_that_looks_like_a_verb(self):
        # namespace literally named "get": consumed as the -n value.
        self.assertEqual(
            cli_families.effective_verbs(["kubectl", "-n", "get", "pods"]),
            ["pods"],
        )

    def test_boolean_global_flags_skip(self):
        self.assertEqual(
            cli_families.effective_verbs(["kubectl", "-A", "get", "pods"]),
            ["get", "pods"],
        )
        self.assertEqual(
            cli_families.effective_verbs(
                ["kubectl", "--all-namespaces", "get", "pods"]
            ),
            ["get", "pods"],
        )

    def test_flags_after_the_verb_are_skipped_too(self):
        self.assertEqual(
            cli_families.effective_verbs(["kubectl", "get", "pods", "-n", "prod"]),
            ["get", "pods"],
        )

    def test_unknown_flag_is_kept_and_breaks_nothing(self):
        self.assertEqual(
            cli_families.effective_verbs(["kubectl", "-w", "get", "pods"]),
            ["-w", "get", "pods"],
        )

    def test_family_without_value_flags(self):
        # vercel declares none: every token stays significant.
        self.assertEqual(
            cli_families.effective_verbs(["vercel", "--token", "list"]),
            ["--token", "list"],
        )

    def test_helm_has_no_declared_flags(self):
        self.assertEqual(
            cli_families.effective_verbs(["helm", "get", "values", "rel"]),
            ["get", "values", "rel"],
        )

    def test_unknown_head_returns_none(self):
        self.assertIsNone(cli_families.effective_verbs(["frobnicate", "get"]))
        self.assertIsNone(cli_families.effective_verbs([]))

    def test_bare_head_returns_empty(self):
        self.assertEqual(cli_families.effective_verbs(["kubectl"]), [])

    def test_dangling_value_flag_at_end(self):
        self.assertEqual(cli_families.effective_verbs(["kubectl", "-n"]), [])


class FamilyRecordTests(unittest.TestCase):
    def test_kubectl_record(self):
        spec = cli_families.FAMILIES["kubectl"]
        self.assertEqual(spec["global_flags"], ("-A", "--all-namespaces"))
        self.assertEqual(
            spec["value_flags"],
            ("-n", "--namespace", "--context", "--cluster", "--kubeconfig"),
        )
        self.assertEqual(
            spec["ro_verbs"],
            (("get",), ("describe",), ("top",), ("events",), ("logs",)),
        )
        # The 4 pre-TK-40 non-cloud specs verbatim + ("exec",) (REQ-02).
        self.assertEqual(
            spec["ask_specs"],
            (("delete",), ("scale",), ("rollout", "undo"), ("apply",),
             ("exec",)),
        )
        self.assertEqual(spec["stream_specs"], ())

    def test_helm_record(self):
        spec = cli_families.FAMILIES["helm"]
        self.assertEqual(spec["global_flags"], ())
        self.assertNotIn("value_flags", spec)  # optional key: not declared
        self.assertEqual(
            spec["ro_verbs"],
            (("template",), ("get", "metadata"), ("list",),
             ("show", "values"), ("show", "chart"), ("status",),
             ("history",)),
        )
        self.assertEqual(spec["ask_specs"], (("uninstall",), ("rollback",)))
        self.assertEqual(spec["stream_specs"], (("get", "values"),))

    def test_manual_kubectl_predicate_is_gone(self):
        # N-F9: a leftover manual _DISPATCH entry (args[1]-only matching)
        # would silently shadow the generated family predicate - the flag-
        # form matrix above goes red if that ever regresses; this pins the
        # dead constant's removal.
        self.assertFalse(hasattr(rewriter, "_KUBECTL_RO"))


class KubectlHelmRewriterTests(unittest.TestCase):
    def assert_rewrite(self, command):
        self.assertEqual(rewriter.rewrite(command), "actx " + command, command)

    def assert_none(self, command):
        self.assertIsNone(rewriter.rewrite(command), command)

    def test_ro_verbs_rewrite(self):
        for command in (
            "kubectl get pods",
            "kubectl describe pod web-abc",
            "kubectl top pods",
            "kubectl events",
            "kubectl logs pod/web-abc",
            "helm template mychart",
            "helm get metadata my-release",
            "helm list",
            "helm show values mychart",
            "helm show chart mychart",
            "helm status my-release",
            "helm history my-release",
        ):
            with self.subTest(command=command):
                self.assert_rewrite(command)

    def test_flag_forms_rewrite(self):
        for command in (
            "kubectl -n prod get pods",
            "kubectl --namespace=prod get pods",
            "kubectl --namespace prod get pods",
            "kubectl -A get pods",
            "kubectl --all-namespaces get pods",
            "kubectl --context ctx describe pod web-abc",
            "kubectl --cluster c1 top pods",
            "kubectl --kubeconfig /tmp/cfg events",
            "kubectl -n prod logs pod/web-abc",
        ):
            with self.subTest(command=command):
                self.assert_rewrite(command)

    def test_mutating_and_escape_verbs_never_rewrite(self):
        for command in (
            "kubectl port-forward pod/web-abc 8080:80",
            "kubectl exec web-abc -- ls",
            "kubectl delete pod x",
            "kubectl apply -f f",
            "kubectl scale deploy app --replicas=0",
            "kubectl rollout undo deployment/app",
            "kubectl edit deploy/x",
            "kubectl patch deploy x",
            "helm uninstall my-release",
            "helm rollback my-release 1",
            "helm install my-release mychart",
            "helm upgrade my-release mychart",
        ):
            with self.subTest(command=command):
                self.assert_none(command)

    def test_watch_and_follow_forms_keep_the_prefix_but_refuse_at_runtime(self):
        # N-F12b: the family table prefix-matches get/logs regardless of
        # -w/-f (pre-TK-40 behavior preserved, see the golden corpus); the
        # runtime refusal lives in hang_policy (never-wrap, exit 125).
        for command in ("kubectl get pods -w", "kubectl logs -f pod/web-abc"):
            with self.subTest(command=command):
                self.assert_rewrite(command)
                self.assertEqual(
                    hang_policy.classify(shlex.split(command)), NEVER_WRAP
                )

    def test_secret_and_stream_verbs_never_rewrite(self):
        # helm get values: stream_specs (deployed values = credential home).
        self.assert_none("helm get values my-release")
        self.assert_none("helm get values my-release -a")
        # kubectl get secret IS prefixed (family table has no object-type
        # rule) and then refused by hang policy with exit 125 - the secret
        # never executes through actx. Pinned here + in the E2E class.
        self.assert_rewrite("kubectl get secret db-creds")

    def test_partial_two_token_verb_needs_full_sequence(self):
        self.assert_none("helm get")
        self.assert_none("helm get valuesx rel")
        self.assert_none("helm show")

    def test_exact_token_equality(self):
        self.assert_none("kubectl getting pods")
        self.assert_none("helm listing")

    def test_existing_guards_inherited(self):
        self.assert_none("kubectl get pods; rm -rf /")  # metachar
        self.assert_none("kubectl get pods && ls")  # metachar
        self.assert_none("actx kubectl get pods")  # idempotency
        self.assert_none("kubectl " + "x" * 4100)  # length guard
        self.assert_none("kubectl 'unbalanced")  # shlex failure

    def test_verbatim_prefix_preserved(self):
        command = "kubectl describe pod 'web abc'"
        self.assertEqual(rewriter.rewrite(command), "actx " + command)

    def test_cloud_families_unchanged(self):
        # The effective_verbs refactor must not move the TK-39 verdicts.
        self.assert_rewrite("vercel --debug list")
        self.assert_none("vercel --token list")  # value-looking-like-verb


class KubectlHelmHangTests(unittest.TestCase):
    def classify(self, command):
        return hang_policy.classify(shlex.split(command))

    def test_watch_flags_after_get_events_never_wrap(self):
        for command in (
            "kubectl get pods -w",
            "kubectl get pods --watch",
            "kubectl events --watch",
            "kubectl events --watch-only",
            "kubectl events -w",
            "kubectl -n prod get pods -w",
            "kubectl get -w pods",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.classify(command), NEVER_WRAP)

    def test_secret_object_types_never_wrap(self):
        for command in (
            "kubectl get secret db-creds",
            "kubectl get secrets",
            "kubectl describe secret db-creds",
            "kubectl get configmap cfg",
            "kubectl get cm cfg",
            "kubectl -n prod get secret db-creds",
            "kubectl describe configmap cfg",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.classify(command), NEVER_WRAP)

    def test_secret_namespace_value_cannot_fake_the_denyset(self):
        # namespace literally named "secret": consumed by -n, no deny.
        self.assertEqual(
            self.classify("kubectl -n secret get pods"), DEFAULT
        )

    def test_helm_get_values_never_wrap(self):
        self.assertEqual(self.classify("helm get values my-release"), NEVER_WRAP)
        self.assertEqual(
            self.classify("helm get values my-release --all"), NEVER_WRAP
        )

    def test_plain_ro_forms_stay_default(self):
        for command in (
            "kubectl -n prod get pods",  # explicit step-7 negative
            "kubectl get pods",
            "kubectl describe pod web-abc",
            "kubectl top pods",
            "kubectl events",
            "kubectl logs pod/web-abc",
            "kubectl get configmaps-x",  # exact token equality
            "helm template mychart",
            "helm list",
            "helm status my-release",
            "helm get metadata my-release",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.classify(command), DEFAULT)

    def test_preexisting_predicates_no_regression(self):
        for command in (
            "kubectl logs -f pod/web-abc",
            "kubectl port-forward pod/web-abc 8080:80",
            "kubectl attach pod/web-abc",
        ):
            with self.subTest(command=command):
                self.assertEqual(self.classify(command), NEVER_WRAP)

    def test_describe_watch_stays_default(self):
        # The watch rule covers get/events only (spec N-F4); describe
        # does not accept -w and the pre-TK-40 verdict is unchanged.
        self.assertEqual(self.classify("kubectl describe pod web-abc -w"), DEFAULT)


class _ShimTestCase(unittest.TestCase):
    """Common plumbing: tmp HOME, tmp bin dir on PATH, marker file."""

    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.bin = tempfile.TemporaryDirectory()
        os.environ["HOME"] = self.home.name
        self.marker = os.path.join(self.bin.name, "shim-ran.marker")

    def tearDown(self):
        os.environ.pop("ACTX_BYPASS", None)
        os.environ.pop("ACTX_MARKER", None)
        del os.environ["HOME"]
        self.bin.cleanup()
        self.home.cleanup()

    def install_shim(self, name, body):
        path = os.path.join(self.bin.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env python3\n")
            handle.write(body)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)

    def run_actx(self, args, stdin_text=None, extra_env=None, timeout=30):
        env = os.environ.copy()
        env["HOME"] = self.home.name
        env["PATH"] = self.bin.name + os.pathsep + env.get("PATH", "")
        env["ACTX_MARKER"] = self.marker
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [ACTX] + args,
            input=stdin_text,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )

    def write_config(self, extra=None):
        config = json.loads(json.dumps(BASE_CONFIG))
        config.update(extra or {})
        path = os.path.join(self.home.name, ".config", "actx", "config.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)


class KubectlHelmShimE2ETests(_ShimTestCase):
    """DoD observable runs on shim executables (tmp PATH injection)."""

    # -- H-F4: `actx kubectl -n prod get pods` -> COMPACT, not passthrough --

    def test_kubectl_n_prod_get_pods_compacts_not_passthrough(self):
        # 3 identical lines collapse to "(x3)": only the dedup compaction
        # path can emit that marker - raw passthrough never would.
        self.install_shim(
            "kubectl",
            "print('NAME READY STATUS RESTARTS AGE')\n"
            "for _ in range(3):\n"
            "    print('web-abc 1/1 Running 0 2h')\n"
            "print('web-def 1/1 Running 0 2h')\n",
        )
        p = self.run_actx(["kubectl", "-n", "prod", "get", "pods"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("web-abc 1/1 Running 0 2h (x3)", p.stdout)
        self.assertIn("web-def", p.stdout)

    def test_kubectl_describe_compacts(self):
        self.install_shim(
            "kubectl",
            "for _ in range(3):\n"
            "    print('Name: web-abc')\n"
            "print('Node: node-1/10.0.0.5')\n",
        )
        p = self.run_actx(["kubectl", "describe", "pod", "web-abc"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("Name: web-abc (x3)", p.stdout)
        self.assertIn("node-1/10.0.0.5", p.stdout)

    def test_kubectl_dash_o_json_compacts_as_json(self):
        payload = json.dumps(
            {"kind": "PodList", "items": [{"name": "web-%02d" % i}
                                          for i in range(40)]}
        )
        self.install_shim("kubectl", "import json\nprint(%r)\n" % payload)
        p = self.run_actx(["kubectl", "get", "pods", "-o", "json"])
        self.assertEqual(p.returncode, 0, p.stderr)
        parsed = json.loads(p.stdout)
        self.assertEqual(parsed["kind"], "PodList")
        self.assertEqual(parsed["items"][0]["name"], "web-00")

    def test_kubectl_exit_code_preserved(self):
        self.install_shim(
            "kubectl", "import sys\nprint('boom')\nsys.exit(3)\n"
        )
        p = self.run_actx(["kubectl", "get", "pods"])
        self.assertEqual(p.returncode, 3)
        self.assertIn("boom", p.stdout)

    def test_helm_template_compacts(self):
        self.install_shim(
            "helm",
            "for _ in range(3):\n"
            "    print('# Source: mychart/templates/svc.yaml')\n"
            "print('kind: Service')\n",
        )
        p = self.run_actx(["helm", "template", "mychart"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("# Source: mychart/templates/svc.yaml (x3)", p.stdout)
        self.assertIn("kind: Service", p.stdout)

    def test_helm_list_compacts(self):
        self.install_shim(
            "helm",
            "print('NAME NAMESPACE REVISION STATUS')\n"
            "print('my-release default 3 deployed')\n",
        )
        p = self.run_actx(["helm", "list"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("my-release", p.stdout)

    # -- never-wrap: exit 125 fast, the shim never runs -------------------

    def _assert_refused_125(self, args, needle):
        start = time.monotonic()
        p = self.run_actx(args, timeout=10)
        elapsed = time.monotonic() - start
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertLess(elapsed, 3.0)
        self.assertIn(needle, p.stderr)
        self.assertFalse(os.path.exists(self.marker))

    def _install_sleeping_shim(self, name):
        self.install_shim(
            name,
            "import os, time\n"
            "open(os.environ['ACTX_MARKER'], 'w').write('x')\n"
            "time.sleep(30)\n",
        )

    def test_get_w_refused_fast(self):
        self._install_sleeping_shim("kubectl")
        self._assert_refused_125(
            ["kubectl", "get", "pods", "-w"], "kubectl get pods -w"
        )

    def test_events_watch_refused_fast(self):
        self._install_sleeping_shim("kubectl")
        self._assert_refused_125(
            ["kubectl", "events", "--watch"], "kubectl events --watch"
        )

    def test_logs_f_refused_fast(self):
        self._install_sleeping_shim("kubectl")
        self._assert_refused_125(
            ["kubectl", "logs", "-f", "pod/web-abc"], "kubectl logs -f pod/web-abc"
        )

    def test_port_forward_refused_fast(self):
        self._install_sleeping_shim("kubectl")
        self._assert_refused_125(
            ["kubectl", "port-forward", "pod/web-abc", "8080:80"],
            "kubectl port-forward",
        )

    def test_helm_get_values_refused_fast(self):
        self._install_sleeping_shim("helm")
        self._assert_refused_125(
            ["helm", "get", "values", "my-release"], "helm get values"
        )
        # Red-gate 16 half 1: the rewriter never prefixes it either.
        self.assertIsNone(rewriter.rewrite("helm get values my-release"))

    # -- red-gate 16: secret object types never captured ------------------

    def test_get_secret_refused_and_secret_never_captured(self):
        # The rewriter prefixes it (family table), actx refuses at 125 BEFORE
        # execution: no stdout, no tee, no history command_text.
        self.write_config(
            {"tee": {"enabled": True, "mode": "always",
                     "dir": "~/.local/share/actx/tee", "min_bytes": 0}}
        )
        self.install_shim(
            "kubectl",
            "import os\n"
            "open(os.environ['ACTX_MARKER'], 'w').write('x')\n"
            "print(%r)\n" % KUBECTL_SECRET_LINE,
        )
        for args in (["kubectl", "get", "secret", "db-creds"],
                     ["run", "kubectl", "get", "secret", "db-creds"],
                     ["kubectl", "-n", "prod", "get", "secret", "db-creds"]):
            with self.subTest(args=args):
                p = self.run_actx(args, timeout=10)
                self.assertEqual(p.returncode, 125, p.stderr)
        self.assertFalse(os.path.exists(self.marker))

        tee_dir = os.path.join(self.home.name, ".local", "share", "actx", "tee")
        self.assertFalse(os.path.exists(tee_dir))

        history = os.path.join(
            self.home.name, ".local", "share", "actx", "history.db"
        )
        if os.path.exists(history):  # nothing is tracked on refusal; be strict
            conn = sqlite3.connect(history)
            try:
                rows = [
                    row[0]
                    for row in conn.execute("SELECT command_text FROM calls")
                ]
            finally:
                conn.close()
            for text in rows:
                self.assertNotIn("cHJvZDpOWnRlN3h1", text or "")

    # -- hook JSON: ask / allow-rewrite -----------------------------------

    def hook_decision(self, command):
        p = self.run_actx(
            ["hook"],
            stdin_text=json.dumps(
                {"tool_name": "Bash", "tool_input": {"command": command}}
            ),
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        if not p.stdout.strip():
            return None
        return json.loads(p.stdout)["hookSpecificOutput"]

    def test_hook_kubectl_exec_asks(self):
        for command in ("kubectl exec pod -- sh",
                        "kubectl -n x exec pod -- ls"):
            with self.subTest(command=command):
                decision = self.hook_decision(command)
                self.assertEqual(decision["permissionDecision"], "ask")
                self.assertIn("kubectl", decision["permissionDecisionReason"])

    def test_hook_helm_uninstall_asks(self):
        decision = self.hook_decision("helm uninstall my-release")
        self.assertEqual(decision["permissionDecision"], "ask")

    def test_hook_kubectl_delete_asks(self):
        decision = self.hook_decision("kubectl delete pod x")
        self.assertEqual(decision["permissionDecision"], "ask")

    def test_hook_kubectl_get_rewritten(self):
        decision = self.hook_decision("kubectl get pods")
        self.assertEqual(decision["permissionDecision"], "allow")
        self.assertEqual(
            decision["updatedInput"]["command"], "actx kubectl get pods"
        )

    def test_hook_kubectl_n_prod_get_rewritten(self):
        decision = self.hook_decision("kubectl -n prod get pods")
        self.assertEqual(decision["permissionDecision"], "allow")
        self.assertEqual(
            decision["updatedInput"]["command"], "actx kubectl -n prod get pods"
        )

    def test_hook_helm_template_rewritten(self):
        decision = self.hook_decision("helm template mychart")
        self.assertEqual(decision["permissionDecision"], "allow")
        self.assertEqual(
            decision["updatedInput"]["command"], "actx helm template mychart"
        )

    def test_hook_helm_get_values_not_rewritten(self):
        # Never an allow-with-rewrite: stream verbs must not gain a prefix.
        decision = self.hook_decision("helm get values my-release")
        self.assertIsNone(decision)

    def test_hook_kubectl_port_forward_not_rewritten(self):
        decision = self.hook_decision("kubectl port-forward pod 8080")
        self.assertIsNone(decision)


if __name__ == "__main__":
    unittest.main()
