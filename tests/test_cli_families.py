"""TK-39: declarative cloud CLI families + custom_heads UX.

Unit tests for the data invariants, rewriter generation, T6 consolidation,
actx-prefix unwrap, hang-policy stream specs, and subprocess E2E runs on
shim executables (tmp dir, PATH injection, no network) - the precedents are
test_run_modes.py and test_hook.py.
"""

import json
import os
import stat
import subprocess
import sqlite3
import tempfile
import time
import unittest

from actx_lib import cli_families, hang_policy, rewriter, security_gate
from actx_lib.installer import INSTRUCTION_SECTION

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTX = os.path.join(ROOT, "actx")

BASE_CONFIG = {
    "tee": {"enabled": False, "mode": "failures", "dir": "~/.local/share/actx/tee"},
    "truncate": {"max_lines": 500, "max_line_chars": 300},
}

# The T6 table as it existed before the TK-39 consolidation (14 heads).
# The consolidated table must contain every entry verbatim (H-F7).
PRE_TK39_T6_ASK_TABLE = {
    "wrangler": (("deploy",), ("publish",), ("delete",)),
    "railway": (("up",), ("delete",), ("remove",), ("down",)),
    "vercel": (("deploy", "--prod"), ("remove",)),
    "netlify": (("deploy",), ("delete",)),
    "supabase": (("delete",), ("db", "reset")),
    "gcloud": (("delete",), ("undeploy",)),
    "kubectl": (("delete",), ("scale",), ("rollout", "undo"), ("apply",)),
    "helm": (("uninstall",), ("rollback",)),
    "docker": (("system", "prune"), ("rm",), ("rmi",), ("compose", "down")),
    "simctl": (("erase",), ("delete",)),
    "flutter": (("clean",),),
    "xcodebuild": (("clean",),),
    "pod": (("deintegrate",),),
    "terraform": (("apply",), ("destroy",)),
}

CLOUD_HEADS = (
    "vercel", "netlify", "railway", "wrangler", "supabase", "flyctl", "gcloud",
)

# docker joined the table in TK-41 (dispatch, T6 specs and hang-policy all
# read the same record); its streaming forms stay in hang_policy._is_docker.
# kubectl and helm followed in TK-40, migrating from hand-written rewriter
# predicates and the non-cloud T6 table into FAMILIES. bq/terraform/
# redis-cli joined in TK-43 (terraform migrated out of the non-cloud T6
# table the same N-F1 way). gh joined in TK-55 (F2).
FAMILY_HEADS = CLOUD_HEADS + (
    "docker", "helm", "kubectl", "bq", "terraform", "redis-cli", "gh",
)

# Secret-bearing connection string whose key AND value contain none of the
# redaction pattern words (secret/token/password/...) - the Q2 adversarial
# fixture. The never-wrap decision is the only thing keeping it out of
# tee/history.
ADVERSARIAL_LINE = "DATABASE_URL=postgres://prod:9xK2q@host/db"

JSON_ARRAY_SHIM = (
    "import json, sys\n"
    "print(json.dumps([{'id': i} for i in range(60)]))\n"
)


class FamilyDataTests(unittest.TestCase):
    def test_families_match_family_heads(self):
        # The name pin died with the eighth family (gh, TK-55): the
        # invariant that matters is FAMILIES == FAMILY_HEADS.
        self.assertEqual(
            tuple(sorted(cli_families.FAMILIES)), tuple(sorted(FAMILY_HEADS))
        )

    def test_schema_shape(self):
        for head, spec in cli_families.FAMILIES.items():
            for key in ("global_flags", "ro_verbs", "ask_specs", "stream_specs"):
                self.assertIn(key, spec, "%s missing %s" % (head, key))
                self.assertIsInstance(spec[key], tuple)
            for flag in spec["global_flags"]:
                self.assertTrue(flag.startswith("-"), (head, flag))
            # value_flags is optional (TK-40); when declared it must be a
            # tuple of flags disjoint from the boolean global_flags.
            if "value_flags" in spec:
                self.assertIsInstance(spec["value_flags"], tuple)
                self.assertEqual(
                    set(spec["value_flags"]) & set(spec["global_flags"]),
                    set(),
                    head,
                )
                for flag in spec["value_flags"]:
                    self.assertTrue(flag.startswith("-"), (head, flag))
            for group in ("ro_verbs", "ask_specs", "stream_specs"):
                for seq in spec[group]:
                    self.assertIsInstance(seq, tuple)
                    self.assertGreater(len(seq), 0, (head, group))
                    for tok in seq:
                        self.assertTrue(tok, (head, seq))
                    # A verb sequence starts with a verb, never a flag
                    # (trailing "--prod" in ask specs is the documented
                    # mandatory-flag form).
                    self.assertFalse(seq[0].startswith("-"), (head, seq))

    def test_verb_groups_pairwise_disjoint(self):
        # Red-gate 10: ro_verbs, ask_specs and stream_specs share no tuple.
        for head, spec in cli_families.FAMILIES.items():
            for a, b in (("ro_verbs", "ask_specs"),
                         ("ro_verbs", "stream_specs"),
                         ("ask_specs", "stream_specs")):
                inter = set(spec[a]) & set(spec[b])
                self.assertEqual(inter, set(), "%s: %s x %s" % (head, a, b))

    def test_actx_skip_lists_are_closed_literals(self):
        self.assertEqual(
            cli_families.ACTX_GLOBAL_FLAGS,
            ("--raw", "--ultra-compact", "-v", "-vv", "-vvv",
             "--version", "--help", "-h"),
        )
        self.assertEqual(cli_families.ACTX_RUN_LITERAL, "run")
        self.assertEqual(
            cli_families.ACTX_RUN_FLAGS, ("--errors", "--failures", "--digest")
        )
        # rewrite/hook take a command string/stdin, not an argv of an
        # executable command: their literals must be absent from every list.
        for literal in ("rewrite", "hook", "init", "tracking", "gain"):
            self.assertNotIn(literal, cli_families.ACTX_GLOBAL_FLAGS)
            self.assertNotIn(literal, cli_families.ACTX_RUN_FLAGS)


class RewriterCloudTests(unittest.TestCase):
    def assert_rewrite(self, command):
        self.assertEqual(rewriter.rewrite(command), "actx " + command, command)

    def assert_none(self, command):
        self.assertIsNone(rewriter.rewrite(command), command)

    def test_ro_verbs_rewrite(self):
        for command in (
            "railway status",
            "railway whoami",
            "railway list",
            "vercel whoami",
            "vercel list",
            "vercel logs",
            "netlify status",
            "netlify sites:list",
            "wrangler whoami",
            "wrangler deployments list",
            "wrangler deployments status",
            "supabase status",
            "supabase projects list",
            "flyctl status",
            "flyctl apps list",
            "flyctl releases",
            "gcloud projects list",
        ):
            with self.subTest(command=command):
                self.assert_rewrite(command)

    def test_global_flags_skipped_with_exact_equality(self):
        self.assert_rewrite("vercel --debug list")
        self.assert_rewrite("vercel -d list")
        self.assert_rewrite("vercel --no-color --non-interactive whoami")
        self.assert_rewrite("supabase --experimental projects list")
        self.assert_rewrite("flyctl --json status")
        self.assert_rewrite("gcloud --quiet projects list")

    def test_value_taking_flag_stops_the_scan(self):
        # --token consumes a value: `vercel --token list` must NOT be read as
        # `vercel list` (conservative non-rewrite).
        self.assert_none("vercel --token list")
        self.assert_none("vercel --cwd app list")

    def test_env_variables_secret_verbs_never_rewrite(self):
        # Q2 blocker decision + N-F4 sibling rule.
        for command in (
            "railway variables",
            "vercel env ls",
            "vercel env pull .env.local",
            "netlify env:get DATABASE_URL",
            "netlify env:list",
            "netlify env:export --file .env",
            "wrangler secret put API_KEY",
            "wrangler secret list",
            "supabase secrets list",
            "flyctl secrets list",
            "gcloud secrets list",
            "gcloud secrets versions access secret-1",
        ):
            with self.subTest(command=command):
                self.assert_none(command)

    def test_mutating_and_ask_verbs_never_rewrite(self):
        for command in (
            "railway up",
            "railway delete",
            "railway remove",
            "railway down",
            "vercel deploy --prod",
            "vercel remove my-project",
            "netlify deploy",
            "netlify delete site",
            "supabase delete",
            "supabase db reset",
            "flyctl deploy",
            "flyctl apps destroy my-app",
            "gcloud projects delete my-proj",
            "gcloud undeploy",
        ):
            with self.subTest(command=command):
                self.assert_none(command)

    def test_exact_token_equality(self):
        self.assert_none("railway statuses")
        self.assert_none("railway statusx")
        self.assert_none("wrangler deployments listing")
        self.assert_none("gcloud project list")

    def test_partial_two_token_verb_needs_full_sequence(self):
        self.assert_none("wrangler deployments")
        self.assert_none("gcloud projects")
        self.assert_none("flyctl apps")

    def test_bare_head_and_unknown_verb(self):
        self.assert_none("railway")
        self.assert_none("railway frobnicate")
        self.assert_none("vercel")

    def test_existing_guards_inherited(self):
        # §7 guards apply to cloud heads unchanged.
        self.assert_none("railway status; rm -rf /")  # metachar
        self.assert_none("railway status && ls")  # metachar
        self.assert_none("actx railway status")  # idempotency
        self.assert_none("railway " + "x" * 4100)  # length guard
        self.assert_none("railway 'unbalanced")  # shlex failure

    def test_verbatim_prefix_preserved(self):
        command = 'vercel logs "my deployment url"'
        self.assertEqual(rewriter.rewrite(command), "actx " + command)

    def test_manual_predicates_not_shadowed(self):
        # docker migrated to the FAMILIES table in TK-41 (the manual
        # _docker_ok predicate is gone): the generated predicate must keep
        # the exact same dispatch behavior.
        self.assertEqual(rewriter.rewrite("docker ps"), "actx docker ps")
        self.assertIsNone(rewriter.rewrite("docker exec x ls"))


class T6ConsolidationTests(unittest.TestCase):
    def test_final_table_superset_of_pre_tk39(self):
        # Red-gate 11/12: every pre-existing spec carried over verbatim (the
        # final table is a SUPERSET). docker gained volume rm/prune in TK-41
        # and kubectl gained ("exec",) in TK-40, so grown heads are checked by
        # per-spec containment, untouched heads stay pinned by exact equality.
        for head, specs in PRE_TK39_T6_ASK_TABLE.items():
            final = security_gate.T6_ASK_TABLE.get(head)
            self.assertIsNotNone(final, head)
            for spec in specs:
                self.assertIn(spec, final, (head, spec))
            if head not in ("docker", "kubectl", "terraform"):
                self.assertEqual(final, specs, head)
        # 4 non-cloud heads + 14 family heads (bq/terraform/redis-cli
        # joined via FAMILIES in TK-43, gh in TK-55; gradlew's ask is a
        # custom gate check, not a table entry).
        self.assertEqual(len(security_gate.T6_ASK_TABLE), 18)

    def test_migrated_heads_left_the_non_cloud_table(self):
        # N-F1 red-gate: a docker/kubectl/helm/terraform record left in
        # _T6_NON_CLOUD_ASK_TABLE would shadow the family specs via
        # setdefault (("volume","rm") / ("exec",) / ("plan","-out") would
        # die) — the snapshot alone would pass vacuously on the stale
        # entries.
        for head in ("docker", "kubectl", "helm", "terraform"):
            self.assertNotIn(head, security_gate._T6_NON_CLOUD_ASK_TABLE)

    def test_migrated_specs_generated_from_families(self):
        # Red-gate 12 positive assertions: the specs come from FAMILIES.
        for head in ("docker", "kubectl", "helm", "terraform"):
            self.assertEqual(
                security_gate.T6_ASK_TABLE[head],
                cli_families.FAMILIES[head]["ask_specs"],
                head,
            )
        self.assertIn(("volume", "rm"), security_gate.T6_ASK_TABLE["docker"])
        self.assertIn(("volume", "prune"), security_gate.T6_ASK_TABLE["docker"])
        self.assertIn(("compose", "down"), security_gate.T6_ASK_TABLE["docker"])
        self.assertIn(("exec",), security_gate.T6_ASK_TABLE["kubectl"])
        self.assertIn(("uninstall",), security_gate.T6_ASK_TABLE["helm"])
        # TK-43: terraform grew ("state",) and ("plan","-out") on top of the
        # two migrated specs.
        self.assertIn(("apply",), security_gate.T6_ASK_TABLE["terraform"])
        self.assertIn(("destroy",), security_gate.T6_ASK_TABLE["terraform"])
        self.assertIn(("state",), security_gate.T6_ASK_TABLE["terraform"])
        self.assertIn(("plan", "-out"), security_gate.T6_ASK_TABLE["terraform"])
        # The pre-wave-2 specs of all four migrated heads are verbatim.
        for head in ("docker", "kubectl", "helm", "terraform"):
            for spec in PRE_TK39_T6_ASK_TABLE[head]:
                self.assertIn(spec, security_gate.T6_ASK_TABLE[head], (head, spec))

    def test_flyctl_ask_specs(self):
        self.assertEqual(
            security_gate.T6_ASK_TABLE["flyctl"], (("deploy",), ("apps", "destroy"))
        )

    def test_cloud_ask_decisions(self):
        cases = (
            ("flyctl deploy", "T6_HIGH_RISK_FLYCTL"),
            ("flyctl apps destroy my-app", "T6_HIGH_RISK_FLYCTL"),
            ("railway delete", "T6_HIGH_RISK_RAILWAY"),
            ("wrangler deploy", "T6_HIGH_RISK_WRANGLER"),
            ("gcloud projects delete x", "T6_HIGH_RISK_GCLOUD"),
        )
        for command, category in cases:
            with self.subTest(command=command):
                decision = security_gate.evaluate_security(command)
                self.assertEqual(decision.decision, "ask", command)
                self.assertEqual(decision.category, category)

    def test_ro_verbs_stay_allow(self):
        for command in (
            "railway status",
            "vercel whoami",
            "wrangler deployments list",
            "supabase projects list",
            "flyctl releases",
            "gcloud projects list",
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    security_gate.evaluate_security(command).decision, "allow"
                )


class DataFamiliesTests(unittest.TestCase):
    """TK-43: bq / terraform / redis-cli family records end to end."""

    def assert_rewrite(self, command):
        self.assertEqual(rewriter.rewrite(command), "actx " + command, command)

    def assert_none(self, command):
        self.assertIsNone(rewriter.rewrite(command), command)

    def test_bq_ro_verbs_rewrite(self):
        self.assert_rewrite("bq ls")
        self.assert_rewrite("bq ls mydataset")
        self.assert_rewrite("bq show mydataset.mytable")
        self.assert_rewrite("bq head mydataset.mytable")
        self.assert_rewrite("bq --format=json ls")
        self.assert_rewrite("bq --format=prettyjson show t")
        self.assert_rewrite("bq --debug_mode ls")
        self.assert_rewrite('bq query --dry_run "SELECT 1"')

    def test_bq_non_ro_stay_unrewritten(self):
        # The executing query form and mutations are TK-52 candidates.
        self.assert_none('bq query "SELECT 1"')
        self.assert_none("bq rm mydataset.mytable")
        self.assert_none("bq update mydataset")
        # Two-token --format form stops the scan (conservative).
        self.assert_none("bq --format json ls")

    def test_terraform_ro_verbs_rewrite(self):
        for command in ("terraform plan", "terraform validate",
                        "terraform show", "terraform version",
                        "terraform graph"):
            with self.subTest(command=command):
                self.assert_rewrite(command)

    def test_terraform_mutation_specs_ask(self):
        for command, category in (
            ("terraform apply", "T6_HIGH_RISK_TERRAFORM"),
            ("terraform apply -auto-approve", "T6_HIGH_RISK_TERRAFORM"),
            ("terraform destroy", "T6_HIGH_RISK_TERRAFORM"),
            ("terraform state rm x", "T6_HIGH_RISK_TERRAFORM"),
            ("terraform state pull", "T6_HIGH_RISK_TERRAFORM"),
            ("terraform plan -out tfplan", "T6_HIGH_RISK_TERRAFORM"),
            ("/usr/local/bin/terraform destroy", "T6_HIGH_RISK_TERRAFORM"),
        ):
            with self.subTest(command=command):
                decision = security_gate.evaluate_security(command)
                self.assertEqual(decision.decision, "ask", command)
                self.assertEqual(decision.category, category, command)

    def test_terraform_ro_stays_allow_and_plan_out_never_rewrites(self):
        self.assertEqual(
            security_gate.evaluate_security("terraform plan").decision, "allow"
        )
        self.assert_rewrite("terraform plan -input=false")
        self.assert_none("terraform plan -out tfplan")
        # Documented limitation: `-out=file` is a single token both the
        # rewriter predicate and the T6 matcher cannot see (wave-2 plan
        # E5.6) - conservative gap, human-approved.
        self.assert_rewrite("terraform plan -out=tfplan")
        self.assertEqual(
            security_gate.evaluate_security("terraform plan -out=tfplan").decision,
            "allow",
        )

    def test_redis_ro_verbs_rewrite_both_cases(self):
        for verb in ("EXISTS", "TTL", "TYPE", "SCAN", "DBSIZE",
                     "exists", "ttl", "type", "scan", "dbsize"):
            with self.subTest(verb=verb):
                self.assert_rewrite("redis-cli %s k" % verb)
        self.assert_rewrite("redis-cli -h myhost EXISTS k")

    def test_redis_destructive_specs_ask_both_cases(self):
        for command in (
            "redis-cli FLUSHALL",
            "redis-cli flushall",
            "redis-cli FLUSHDB",
            "redis-cli flushdb",
            "redis-cli config set maxmemory 100",
            "redis-cli CONFIG SET maxmemory 100",
            "redis-cli Config Set maxmemory 100",
        ):
            with self.subTest(command=command):
                decision = security_gate.evaluate_security(command)
                self.assertEqual(decision.decision, "ask", command)
                self.assertEqual(
                    decision.category, "T6_HIGH_RISK_REDIS-CLI", command
                )

    def test_redis_get_is_never_wrap_both_cases_and_behind_value_flags(self):
        # Q2 wave-1 rule: GET prints raw values -> never-wrap (TK-52 reviews).
        for argv in (["redis-cli", "GET", "k"], ["redis-cli", "get", "k"],
                     ["redis-cli", "-h", "myhost", "GET", "k"],
                     ["redis-cli", "-p", "6379", "get", "k"]):
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), "never_wrap")

    def test_redis_ro_and_monitor_classes(self):
        self.assertEqual(
            hang_policy.classify(["redis-cli", "EXISTS", "k"]), "default"
        )
        self.assertEqual(hang_policy.classify(["redis-cli", "DBSIZE"]), "default")
        # MONITOR stays in the dedicated predicate, not stream_specs (the
        # wrangler-tail precedent): still never-wrap in any case.
        self.assertEqual(
            hang_policy.classify(["redis-cli", "MONITOR"]), "never_wrap"
        )
        self.assertEqual(
            hang_policy.classify(["redis-cli", "monitor"]), "never_wrap"
        )

    def test_redis_value_flags_skip_their_values(self):
        # `-h EXISTS` is host "EXISTS": the value is consumed with the flag
        # and can never impersonate a verb - GET alone is the effective verb.
        verbs = cli_families.effective_verbs(["redis-cli", "-h", "EXISTS", "GET"])
        self.assertEqual(verbs, ["GET"])


class GhFamilyTests(unittest.TestCase):
    """TK-55 F2: gh family record — ro verbs rewrite, mutations ask via
    T6, and the file-writing/secret-bearing namespaces defer (they live
    in no list at all)."""

    def assert_rewrite(self, command):
        self.assertEqual(rewriter.rewrite(command), "actx " + command, command)

    def assert_none(self, command):
        self.assertIsNone(rewriter.rewrite(command), command)

    def test_gh_ro_verbs_rewrite(self):
        for command in (
            "gh pr list",
            "gh pr view 12",
            "gh pr status",
            "gh pr diff 12",
            "gh pr checks",
            "gh issue list",
            "gh issue view 3",
            "gh issue status",
            "gh run list",
            "gh run view 55",
            "gh repo list",
            "gh repo view",
            "gh release list",
            "gh release view v1.0",
            "gh workflow list",
            "gh workflow view",
            "gh search issues actx",
            "gh gist list",
        ):
            with self.subTest(command=command):
                self.assert_rewrite(command)

    def test_gh_repo_value_flag_skipped(self):
        # -R/--repo consume a value token; the effective verb still
        # resolves behind them.
        self.assert_rewrite("gh pr -R o/r list")
        self.assert_rewrite("gh issue --repo o/r list")
        self.assert_rewrite("gh --repo=o/r pr list")

    def test_gh_mutating_verbs_never_rewrite(self):
        for command in (
            "gh pr merge",
            "gh pr create --fill",
            "gh pr close 12",
            "gh pr reopen 12",
            "gh pr comment 12",
            "gh pr edit 12",
            "gh pr review --approve",
            "gh pr checkout 12",
            "gh pr ready 12",
            "gh pr revert 12",
            "gh pr update-branch 12",
            "gh issue create",
            "gh issue comment 3",
            "gh issue delete 3",
            "gh issue develop 3",
            "gh run delete 55",
            "gh run cancel 55",
            "gh run rerun 55",
            "gh repo create x",
            "gh repo clone o/r",
            "gh repo delete x",
            "gh repo sync x",
            "gh release create v1",
            "gh release upload v1 f.zip",
            "gh release delete-asset v1 a.zip",
            "gh workflow run ci.yml",
            "gh workflow disable ci.yml",
            "gh gist create f.py",
            "gh gist delete 5b0e",
            "gh gist clone 5b0e",
        ):
            with self.subTest(command=command):
                self.assert_none(command)

    def test_gh_no_list_namespaces_defer(self):
        # In NO FAMILIES list — plain defer: downloads write files into
        # cwd (N-F4 sibling rule), auth/secret/variable handle credential
        # material, api is an arbitrary HTTP verb surface, `repo
        # autolink`/`repo deploy-key` are mixed read/write sub-namespaces
        # and a bare namespace or unknown verb has no class at all.
        for command in (
            "gh run download 55",
            "gh release download v1",
            "gh auth token",
            "gh auth login",
            "gh api repos",
            "gh api -X DELETE repos/o/r",
            "gh secret list",
            "gh secret set KEY",
            "gh variable get X",
            "gh repo autolink list",
            "gh pr frobnicate",
            "gh workflow",
        ):
            with self.subTest(command=command):
                self.assert_none(command)

    def test_gh_ask_specs_reach_t6(self):
        # The family ask_specs merge into T6_ASK_TABLE verbatim.
        self.assertEqual(
            security_gate.T6_ASK_TABLE["gh"],
            cli_families.FAMILIES["gh"]["ask_specs"],
        )
        for command in (
            "gh pr merge",
            "gh pr checkout 12",
            "gh issue create",
            "gh run delete 55",
            "gh repo clone o/r",
        ):
            with self.subTest(command=command):
                decision = security_gate.evaluate_security(command)
                self.assertEqual(decision.decision, "ask", command)
                self.assertEqual(decision.category, "T6_HIGH_RISK_GH", command)

    def test_gh_ro_verbs_stay_allow(self):
        for command in (
            "gh pr list",
            "gh pr checks",
            "gh issue status",
            "gh run view 55",
            "gh repo view",
            "gh release list",
            "gh search issues actx",
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    security_gate.evaluate_security(command).decision, "allow"
                )

    def test_gh_stream_specs_never_wrap(self):
        # `run watch` and `pr checks --watch` wait on remote state.
        for argv in (
            ["gh", "run", "watch"],
            ["gh", "pr", "checks", "--watch"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), "never_wrap")
        # The non-watch forms stay on the default class.
        self.assertEqual(
            hang_policy.classify(["gh", "pr", "checks"]), "default"
        )
        self.assertEqual(
            hang_policy.classify(["gh", "run", "view", "55"]), "default"
        )


class RunPrefixSplitTests(unittest.TestCase):
    """TK-55 F3/F4: shared exec-prefix scanner — pure and fail-safe (any
    anomaly returns None; callers keep the original tokens)."""

    def test_uv_run_split_matrix(self):
        cases = (
            (["uv", "run", "pytest", "-q"],
             (["pytest", "-q"], ["uv", "run"])),
            (["uv", "run", "--with", "requests", "python", "x.py"],
             (["python", "x.py"], ["uv", "run", "--with", "requests"])),
            (["uv", "run", "--env-file", ".env", "pytest"],
             (["pytest"], ["uv", "run", "--env-file", ".env"])),
            # `--flag=value` form of a value flag.
            (["uv", "run", "--with=requests", "pytest"],
             (["pytest"], ["uv", "run", "--with=requests"])),
            # Boolean prefix flags are skipped singly.
            (["uv", "run", "--no-sync", "--isolated", "pytest"],
             (["pytest"], ["uv", "run", "--no-sync", "--isolated"])),
        )
        for tokens, expected in cases:
            with self.subTest(tokens=tokens):
                self.assertEqual(
                    cli_families.run_prefix_split(tokens), expected
                )

    def test_uv_run_env_file_value_stays_in_consumed(self):
        # REQ-04: the skipped prefix tokens (file-valued flags included)
        # stay visible to token-level scans via `consumed`.
        inner, consumed = cli_families.run_prefix_split(
            ["uv", "run", "--env-file", ".env", "pytest"]
        )
        self.assertEqual(inner, ["pytest"])
        self.assertIn(".env", consumed)
        self.assertIn("--env-file", consumed)

    def test_uv_run_anomalies_return_none(self):
        for tokens in (
            ["uv", "run", "--unknownflag", "pytest"],  # unknown flag: bail
            ["uv", "run"],                             # no inner command
            ["uv", "run", "--with"],                   # dangling value flag
            ["uv", "sync"],                            # verb is not `run`
            ["uv"],                                    # bare head
        ):
            with self.subTest(tokens=tokens):
                self.assertIsNone(cli_families.run_prefix_split(tokens))

    def test_xcrun_split_matrix(self):
        cases = (
            (["xcrun", "simctl", "erase", "all"],
             (["simctl", "erase", "all"], ["xcrun"])),
            (["xcrun", "--sdk", "macosx", "simctl", "list"],
             (["simctl", "list"], ["xcrun", "--sdk", "macosx"])),
            (["xcrun", "--toolchain", "tc", "--log", "simctl", "list"],
             (["simctl", "list"], ["xcrun", "--toolchain", "tc", "--log"])),
        )
        for tokens, expected in cases:
            with self.subTest(tokens=tokens):
                self.assertEqual(
                    cli_families.run_prefix_split(tokens), expected
                )

    def test_xcrun_anomalies_return_none(self):
        for tokens in (
            ["xcrun", "otool", "x"],          # tool is not simctl
            ["xcrun"],                        # no tool at all
            ["xcrun", "--sdk"],               # dangling value flag
            ["xcrun", "--bogus", "simctl"],   # unknown flag: bail
        ):
            with self.subTest(tokens=tokens):
                self.assertIsNone(cli_families.run_prefix_split(tokens))

    def test_double_dash_end_of_options(self):
        # Acceptance finding: `uv run -- <cmd>` is a live bypass — uv honors
        # the POSIX separator and executes the inner command verbatim.
        inner, consumed = cli_families.run_prefix_split(
            ["uv", "run", "--", "rm", "-rf", "~"]
        )
        self.assertEqual(inner, ["rm", "-rf", "~"])
        self.assertEqual(consumed, ["uv", "run", "--"])
        inner, consumed = cli_families.run_prefix_split(
            ["uv", "run", "-p", "3.12", "--", "python", "x.py"]
        )
        self.assertEqual(inner, ["python", "x.py"])
        inner, _ = cli_families.run_prefix_split(
            ["xcrun", "--", "simctl", "erase", "all"]
        )
        self.assertEqual(inner, ["simctl", "erase", "all"])

    def test_double_dash_anomalies(self):
        for tokens in (
            ["uv", "run", "--"],                    # nothing after --
            ["xcrun", "--", "otool", "x"],          # -- does not bypass only_tool
        ):
            with self.subTest(tokens=tokens):
                self.assertIsNone(cli_families.run_prefix_split(tokens))

    def test_absolute_path_head_unwraps(self):
        # Absolute-path invocation matches by basename — zero-import
        # constraint keeps this inside run_prefix_split.
        inner, consumed = cli_families.run_prefix_split(
            ["/usr/bin/uv", "run", "rm", "-rf", "~"]
        )
        self.assertEqual(inner, ["rm", "-rf", "~"])
        inner, _ = cli_families.run_prefix_split(
            ["/usr/bin/xcrun", "simctl", "erase", "all"]
        )
        self.assertEqual(inner, ["simctl", "erase", "all"])

    def test_non_prefix_heads_return_none(self):
        for tokens in (
            ["pytest", "-q"],
            ["env", "uv", "run", "pytest"],  # head is env, not uv
            [],
        ):
            with self.subTest(tokens=tokens):
                self.assertIsNone(cli_families.run_prefix_split(tokens))


class GradleTaskClassTests(unittest.TestCase):
    """TK-55 F5: positional task classification on the last `:`-segment —
    ask markers beat ro bases, everything else is unknown."""

    def test_class_matrix(self):
        cases = (
            (":app:assembleDebug", "ro"),
            ("test", "ro"),
            ("testDebugUnitTest", "ro"),
            ("buildNeeded", "ro"),
            ("publish", "ask"),
            (":app:publish", "ask"),
            (":app:clean", "ask"),
            # ASK wins over the ro-base prefix.
            ("assembleAndPublish", "ask"),
            ("publishToMavenLocal", "ask"),
            ("clean", "ask"),
            ("weirdTask", "unknown"),
        )
        for token, expected in cases:
            with self.subTest(token=token):
                self.assertEqual(cli_families.gradle_task_class(token), expected)


class ActxUnwrapTests(unittest.TestCase):
    """REQ-07: T-tables match under `actx [flags] [run [flags]] <tool> ...`."""

    def test_actx_run_kubectl_delete_asks(self):
        decision = security_gate.evaluate_security("actx run kubectl delete pod x")
        self.assertEqual(decision.decision, "ask")
        self.assertEqual(decision.category, "T6_HIGH_RISK_KUBECTL")

    def test_actx_run_railway_delete_asks(self):
        decision = security_gate.evaluate_security("actx run railway delete")
        self.assertEqual(decision.decision, "ask")
        self.assertEqual(decision.category, "T6_HIGH_RISK_RAILWAY")

    def test_actx_raw_run_railway_delete_still_asks(self):
        # Intentional: ask outranks --raw semantics.
        decision = security_gate.evaluate_security(
            "actx --raw run railway delete"
        )
        self.assertEqual(decision.decision, "ask")
        self.assertEqual(decision.category, "T6_HIGH_RISK_RAILWAY")

    def test_global_and_run_flag_forms_unwrap(self):
        for command in (
            "actx railway delete",
            "actx -v run railway delete",
            "actx --ultra-compact run railway delete",
            "actx run --digest railway delete",
            "/usr/local/bin/actx run railway delete",
            "actx run flyctl deploy",
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    security_gate.evaluate_security(command).decision, "ask"
                )

    def test_t1_matches_behind_actx_run(self):
        decision = security_gate.evaluate_security("actx run cat .env")
        self.assertEqual(decision.decision, "deny")
        self.assertEqual(decision.category, "T1_CREDENTIAL_ACCESS")

    def test_env_deny_parity_behind_actx(self):
        # Red-gate 9: `actx run env` denies exactly like bare `env`.
        for command in ("env", "actx run env", "actx --raw run env",
                        "actx run env FOO=1", "actx env"):
            with self.subTest(command=command):
                decision = security_gate.evaluate_security(command)
                self.assertEqual(decision.decision, "deny", command)
                self.assertEqual(decision.category, "T1_CREDENTIAL_ACCESS")

    def test_env_with_command_keeps_normal_verdict(self):
        self.assertEqual(
            security_gate.evaluate_security("actx run env git status").decision,
            security_gate.evaluate_security("env git status").decision,
        )

    def test_rewrite_and_hook_inputs_not_unwrapped(self):
        # Their argument is a command string/stdin, not an argv to execute.
        for command in ('actx rewrite "ls"', "actx hook", "actx rewrite"):
            with self.subTest(command=command):
                self.assertEqual(
                    security_gate.evaluate_security(command).decision, "allow"
                )

    def test_unknown_flag_not_skipped(self):
        # Closed literal lists: an unknown flag stops unwrapping (never
        # treated as transparent).
        self.assertEqual(
            security_gate.evaluate_security(
                "actx --nonsense run railway delete"
            ).decision,
            "allow",
        )

    def test_bare_actx_forms_allow(self):
        for command in ("actx", "actx run", "actx --raw", "actx --version"):
            with self.subTest(command=command):
                self.assertEqual(
                    security_gate.evaluate_security(command).decision, "allow"
                )


class HangPolicyCloudTests(unittest.TestCase):
    def test_stream_specs_never_wrap(self):
        cases = (
            ["railway", "logs", "-f"],
            ["railway", "logs"],
            ["railway", "variables"],
            ["vercel", "env", "ls"],
            ["vercel", "logs", "--follow", "x"],
            ["vercel", "logs", "-f"],
            ["netlify", "watch"],
            ["netlify", "logs"],
            ["wrangler", "secret", "put", "K"],
            ["supabase", "secrets", "list"],
            ["flyctl", "logs"],
            ["flyctl", "ssh", "console"],
            ["gcloud", "secrets", "versions", "access", "s"],
        )
        for argv in cases:
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), "never_wrap")

    def test_global_flags_skipped_before_stream_verb(self):
        self.assertEqual(
            hang_policy.classify(["flyctl", "--json", "logs"]), "never_wrap"
        )
        self.assertEqual(
            hang_policy.classify(["supabase", "--experimental", "secrets"]),
            "never_wrap",
        )

    def test_ro_verbs_stay_default(self):
        for argv in (
            ["railway", "status"],
            ["vercel", "whoami"],
            ["netlify", "status"],
            ["wrangler", "deployments", "list"],
            ["supabase", "projects", "list"],
            ["flyctl", "apps", "list"],
            ["gcloud", "projects", "list"],
        ):
            with self.subTest(argv=argv):
                self.assertEqual(hang_policy.classify(argv), "default")

    def test_login_and_tail_predicates_not_duplicated(self):
        # Still covered by their dedicated predicates (H-F9 verification).
        self.assertEqual(hang_policy.classify(["railway", "login"]), "never_wrap")
        self.assertEqual(hang_policy.classify(["wrangler", "tail"]), "never_wrap")
        self.assertEqual(
            hang_policy.classify(["gcloud", "auth", "login"]), "never_wrap"
        )


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


class CloudShimE2ETests(_ShimTestCase):
    """DoD observable runs on shim executables (tmp PATH injection)."""

    # -- DoD: `actx railway status` (JSON shim) -> compact ----------------

    def test_railway_status_compacts_json_output(self):
        payload = json.dumps(
            {"service": "web", "env": "production",
             "items": [{"id": i} for i in range(60)]}
        )
        self.install_shim("railway", "import sys\nprint(%r)\n" % payload)
        p = self.run_actx(["railway", "status"])
        self.assertEqual(p.returncode, 0, p.stderr)
        obj = json.loads(p.stdout)
        self.assertEqual(obj["service"], "web")
        self.assertIn("items omitted", p.stdout)

    def test_gcloud_projects_list_compacts(self):
        payload = json.dumps([{"projectId": "p%02d" % i} for i in range(40)])
        self.install_shim("gcloud", "import sys\nprint(%r)\n" % payload)
        p = self.run_actx(["gcloud", "projects", "list"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("items omitted", p.stdout)
        self.assertEqual(json.loads(p.stdout)[0], {"projectId": "p00"})

    # -- DoD: `actx railway logs -f` (sleeping shim) -> exit 125 fast -----

    def test_railway_logs_f_refused_fast_without_execution(self):
        self.install_shim(
            "railway",
            "import os, time\n"
            "open(os.environ['ACTX_MARKER'], 'w').write('x')\n"
            "time.sleep(30)\n",
        )
        start = time.monotonic()
        p = self.run_actx(["railway", "logs", "-f"], timeout=10)
        elapsed = time.monotonic() - start
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertLess(elapsed, 3.0)
        self.assertIn("railway logs -f", p.stderr)
        # Refused before launch: the shim never ran.
        self.assertFalse(os.path.exists(self.marker))

    def test_railway_variables_refused_without_rewrite(self):
        self.assertIsNone(rewriter.rewrite("railway variables"))
        self.install_shim(
            "railway",
            "import os\n"
            "open(os.environ['ACTX_MARKER'], 'w').write('x')\n"
            "print(%r)\n" % ADVERSARIAL_LINE,
        )
        p = self.run_actx(["railway", "variables"], timeout=10)
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertNotIn("DATABASE_URL", p.stdout + p.stderr)
        self.assertFalse(os.path.exists(self.marker))

    # -- Q2 adversarial red-gate: no tee, no history command_text  --------

    def test_adversarial_secret_never_reaches_tee_or_history(self):
        self.write_config(
            {"tee": {"enabled": True, "mode": "always",
                     "dir": "~/.local/share/actx/tee", "min_bytes": 0}}
        )
        self.install_shim(
            "railway",
            "import os\n"
            "open(os.environ['ACTX_MARKER'], 'w').write('x')\n"
            "print(%r)\n" % ADVERSARIAL_LINE,
        )
        # Both entry routes refuse before execution: bare head and `actx run`.
        for args in (["railway", "variables"], ["run", "railway", "variables"]):
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
                self.assertNotIn("postgres://prod", text or "")
                self.assertNotIn(ADVERSARIAL_LINE, text or "")

    # -- DoD: hook-JSON -> ask / allow-rewrite / no-rewrite ---------------

    def test_hook_railway_delete_asks(self):
        p = self.run_actx(
            ["hook"],
            stdin_text=json.dumps(
                {"tool_name": "Bash",
                 "tool_input": {"command": "railway delete"}}
            ),
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        decision = json.loads(p.stdout)["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "ask")
        self.assertIn("railway", decision["permissionDecisionReason"])

    def test_hook_actx_run_railway_delete_asks(self):
        p = self.run_actx(
            ["hook"],
            stdin_text=json.dumps(
                {"tool_name": "Bash",
                 "tool_input": {"command": "actx run railway delete"}}
            ),
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        decision = json.loads(p.stdout)["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "ask")

    def test_hook_railway_status_rewritten(self):
        p = self.run_actx(
            ["hook"],
            stdin_text=json.dumps(
                {"tool_name": "Bash",
                 "tool_input": {"command": "railway status"}}
            ),
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(
            data["hookSpecificOutput"]["updatedInput"]["command"],
            "actx railway status",
        )

    def test_hook_env_secret_verbs_not_rewritten(self):
        for command in ("vercel env pull .env.local",
                        "wrangler secret put API_KEY",
                        "railway variables"):
            with self.subTest(command=command):
                p = self.run_actx(
                    ["hook"],
                    stdin_text=json.dumps(
                        {"tool_name": "Bash",
                         "tool_input": {"command": command}}
                    ),
                )
                self.assertEqual(p.returncode, 0, p.stderr)
                # Never rewritten to an actx command: either the hook
                # defers silently (empty stdout) or the gate denies/asks
                # (`vercel env pull .env.local` denies on the .env.local
                # path - stricter and welcome). What must never appear is
                # an allow-with-rewrite.
                self.assertNotIn("updatedInput", p.stdout)
                if p.stdout.strip():
                    decision = json.loads(p.stdout)["hookSpecificOutput"][
                        "permissionDecision"
                    ]
                    self.assertIn(decision, ("deny", "ask", "force_ask"))


class DockerShimE2ETests(_ShimTestCase):
    """TK-41 DoD on shims: bare `docker stats` refused fast (exit 125),
    `stats --no-stream` rewritten + compacted, `inspect` JSON compacted."""

    def test_bare_stats_refused_fast_without_execution(self):
        # `docker stats` streams; the hook never rewrites it, and a manual
        # `actx docker stats` is refused before launch.
        self.assertIsNone(rewriter.rewrite("docker stats"))
        self.install_shim(
            "docker",
            "import os, time\n"
            "open(os.environ['ACTX_MARKER'], 'w').write('x')\n"
            "time.sleep(30)\n",
        )
        start = time.monotonic()
        p = self.run_actx(["docker", "stats"], timeout=10)
        elapsed = time.monotonic() - start
        self.assertEqual(p.returncode, 125, p.stderr)
        self.assertLess(elapsed, 3.0)
        self.assertIn("docker stats", p.stderr)
        # Refused before launch: the shim never ran.
        self.assertFalse(os.path.exists(self.marker))

    def test_stats_no_stream_rewritten_and_compacted(self):
        self.assertEqual(
            rewriter.rewrite("docker stats --no-stream"),
            "actx docker stats --no-stream",
        )
        self.install_shim(
            "docker",
            "import os\n"
            "open(os.environ['ACTX_MARKER'], 'w').write('x')\n"
            "for _ in range(60):\n"
            "    print('web  0.15%  120MiB / 4GiB')\n",
        )
        p = self.run_actx(["docker", "stats", "--no-stream"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("(x60)", p.stdout)
        self.assertTrue(os.path.exists(self.marker))

    def test_inspect_json_compacted(self):
        payload = json.dumps(
            [{"Id": "abc123def456", "Image": "nginx:1",
              "State": {"Status": "running", "Running": True}}]
        )
        self.install_shim("docker", "import sys\nprint(%r)\n" % payload)
        p = self.run_actx(["docker", "inspect", "web"])
        self.assertEqual(p.returncode, 0, p.stderr)
        obj = json.loads(p.stdout)
        self.assertEqual(obj[0]["Id"], "abc123def456")
        self.assertEqual(obj[0]["State"]["Status"], "running")


class CustomHeadsTests(_ShimTestCase):
    """TK-39 custom_heads UX; fixed precedence raw/bypass -> REGISTRY ->
    custom_heads -> unknown (asserted below in that order)."""

    def test_custom_head_behaves_like_run(self):
        self.write_config({"custom_heads": ["mytool"]})
        self.install_shim("mytool", JSON_ARRAY_SHIM)
        p = self.run_actx(["mytool", "get"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("items omitted", p.stdout)
        self.assertEqual(json.loads(p.stdout)[0], {"id": 0})

    def test_precedence_registry_over_custom_heads(self):
        # `ls` is a REGISTRY head: declaring it custom changes nothing. The
        # run_ls filter prints a "name (N):" group header; the generic
        # runner path (raw `ls -1` style output) never does.
        target = os.path.join(self.home.name, "probe")
        os.makedirs(target)
        for name in ("a.txt", "b.txt", "c.txt"):
            with open(os.path.join(target, name), "w", encoding="utf-8") as h:
                h.write("x")
        self.write_config({"custom_heads": ["ls"]})
        p = self.run_actx(["ls", target])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("(3)", p.stdout)
        self.assertIn("a.txt", p.stdout)

    def test_precedence_builtin_over_custom_heads(self):
        self.write_config({"custom_heads": ["run"]})
        p = self.run_actx(["run"])
        # Builtin branch answers before any config lookup.
        self.assertEqual(p.returncode, 1)
        self.assertIn("run requires a command", p.stderr)
        self.assertNotIn("ignoring reserved custom head", p.stderr)

    def test_precedence_raw_over_custom_heads(self):
        self.write_config({"custom_heads": ["mytool"]})
        self.install_shim("mytool", JSON_ARRAY_SHIM)
        p = self.run_actx(["--raw", "mytool", "get"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("items omitted", p.stdout)  # unfiltered passthrough

    def test_precedence_bypass_env_over_custom_heads(self):
        self.write_config({"custom_heads": ["mytool"]})
        self.install_shim("mytool", JSON_ARRAY_SHIM)
        p = self.run_actx(["mytool", "get"], extra_env={"ACTX_BYPASS": "1"})
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("items omitted", p.stdout)

    def test_reserved_names_ignored_with_warning(self):
        self.write_config({"custom_heads": ["cat", "mytool"]})
        self.install_shim("mytool", "print('ok')\n")
        # cat is reserved (REGISTRY): warned about, while mytool still works.
        p = self.run_actx(["mytool", "get"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("ok", p.stdout)
        self.assertIn("ignoring reserved custom head: cat", p.stderr)

    def test_undeclared_head_error_mentions_run(self):
        self.write_config({"custom_heads": ["mytool"]})
        p = self.run_actx(["othertool", "x"])
        self.assertEqual(p.returncode, 1)
        self.assertIn("error: unknown command: othertool", p.stderr)
        self.assertIn("actx run othertool", p.stderr)

    def test_invalid_custom_heads_values_ignored(self):
        self.write_config({"custom_heads": ["mytool", 7, None, "", {"x": 1}]})
        self.install_shim("mytool", "print('ok')\n")
        p = self.run_actx(["mytool", "get"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("ok", p.stdout)
        p = self.run_actx(["othertool", "x"])
        self.assertEqual(p.returncode, 1)
        self.assertIn("actx run othertool", p.stderr)

    def test_non_list_custom_heads_is_ignored(self):
        config = json.loads(json.dumps(BASE_CONFIG))
        config["custom_heads"] = "mytool"
        path = os.path.join(self.home.name, ".config", "actx", "config.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)
        p = self.run_actx(["mytool", "get"])
        self.assertEqual(p.returncode, 1)
        self.assertIn("error: unknown command: mytool", p.stderr)


class ConfigCustomHeadsTests(unittest.TestCase):
    def test_default_has_empty_custom_heads_and_merges_in(self):
        from actx_lib import config

        self.assertEqual(config.DEFAULT_CONFIG["custom_heads"], [])
        with tempfile.TemporaryDirectory() as home:
            old = os.environ.get("HOME")
            os.environ["HOME"] = home
            try:
                loaded = config.load()
            finally:
                if old is None:
                    os.environ.pop("HOME", None)
                else:
                    os.environ["HOME"] = old
        # Additive key: an existing config gains the default via merge.
        self.assertEqual(loaded["custom_heads"], [])


class InstructionSectionTests(unittest.TestCase):
    def test_cloud_heads_in_instruction_section(self):
        self.assertIn("`vercel whoami`", INSTRUCTION_SECTION)
        self.assertIn("`railway status`", INSTRUCTION_SECTION)
        self.assertIn("`wrangler deployments list`", INSTRUCTION_SECTION)

    def test_init_regenerates_section_from_stale_body(self):
        # REQ-03 / TK-30 regression: replace-in-place, no duplication.
        stale = (
            "## Output compression (actx)\n\n"
            "To reduce context noise, prefix read-only commands"
            " with `actx`:\n- `git status` → `actx git status`\n\n"
            "For full output, run without `actx`.\n"
        )
        with tempfile.TemporaryDirectory() as home:
            rules = os.path.join(home, ".grok", "rules", "actx.md")
            os.makedirs(os.path.dirname(rules), exist_ok=True)
            with open(rules, "w", encoding="utf-8") as handle:
                handle.write("Other rules\n\n" + stale)
            env = os.environ.copy()
            env["HOME"] = home
            for _ in range(2):
                p = subprocess.run(
                    [ACTX, "init", "--agent", "grok"],
                    capture_output=True,
                    text=True,
                    env=env,
                )
                self.assertEqual(p.returncode, 0, p.stderr)
            with open(rules, encoding="utf-8") as handle:
                content = handle.read()
            self.assertIn(INSTRUCTION_SECTION, content)
            self.assertIn("`railway status`", content)
            self.assertEqual(
                content.count("## Output compression (actx)"), 1
            )
            self.assertNotIn("prefix read-only commands", content)


if __name__ == "__main__":
    unittest.main()
