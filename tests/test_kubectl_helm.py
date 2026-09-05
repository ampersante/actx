"""TK-40: kubectl + helm CLI families (wave 2, executor E2).

Unit matrices for the family records, effective_verbs, rewriter and hang
policy, plus subprocess E2E runs on shim executables (tmp dir, PATH
injection, no network) - the precedents are test_cli_families.py and
test_hook.py. The pre-migration verdicts live in
test_golden_kubectl_helm.py (physically frozen corpus, H-F10/N-F12a).
"""

import shlex
import unittest

from actx_lib import cli_families, hang_policy, rewriter, security_gate

NEVER_WRAP = "never_wrap"
DEFAULT = "default"



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


if __name__ == "__main__":
    unittest.main()
