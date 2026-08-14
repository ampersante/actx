from actx_lib.filters import git_filter, read_filter, system_filter

REGISTRY = {
    "git": git_filter.run,
    "ls": system_filter.run_ls,
    "grep": system_filter.run_grep,
    "find": system_filter.run_find,
    "read": read_filter.run,
}
