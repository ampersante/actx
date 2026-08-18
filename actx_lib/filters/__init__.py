from actx_lib import runner
from actx_lib.filters import (
    git_filter,
    infra_filter,
    linter_filter,
    package_filter,
    read_filter,
    smart_filter,
    system_filter,
    test_runner_filter,
    tree_filter,
)

REGISTRY = {
    "git": git_filter.run,
    "ls": system_filter.run_ls,
    "grep": system_filter.run_grep,
    "find": system_filter.run_find,
    "wc": system_filter.run_wc,
    "head": system_filter.run_head,
    "tail": system_filter.run_tail,
    "sort": system_filter.run_sort,
    "uniq": system_filter.run_uniq,
    "rg": system_filter.run_rg,
    "cat": system_filter.run_cat,
    "read": read_filter.run,
    "smart": smart_filter.run,
    "tree": tree_filter.run,
    "pytest": test_runner_filter.run_pytest,
    "jest": test_runner_filter.run_jest,
    "vitest": test_runner_filter.run_vitest,
    "ruff": linter_filter.run_ruff,
    "tsc": linter_filter.run_tsc,
    "eslint": linter_filter.run_eslint,
    "golangci-lint": linter_filter.run_golangci_lint,
    "next": linter_filter.run_next,
    "pip": package_filter.run_pip,
    "uv": package_filter.run_uv,
    "npm": package_filter.run_npm,
    "pnpm": package_filter.run_pnpm,
    "docker": infra_filter.run_docker,
    "kubectl": infra_filter.run_kubectl,
    "gh": infra_filter.run_gh,
    "aws": infra_filter.run_aws,
}


def _run_cargo(args, config):
    if not args:
        return runner.run_passthrough(["cargo"])
    if args[0] == "test":
        return test_runner_filter.run_cargo_test(args, config)
    if args[0] in ("build", "clippy"):
        return linter_filter.run_cargo(args, config)
    return runner.run_passthrough(["cargo"] + args)


def _run_go(args, config):
    if args and args[0] == "test":
        return test_runner_filter.run_go_test(args, config)
    return runner.run_passthrough(["go"] + args)


REGISTRY["cargo"] = _run_cargo
REGISTRY["go"] = _run_go
