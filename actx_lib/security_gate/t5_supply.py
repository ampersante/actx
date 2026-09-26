"""actx security gate - T5: supply chain & package lifecycle security
(TK-59 split).

Body unchanged from the pre-split monolith - see tools/ast_identity_check.py.
"""

import os

from .common import SecurityDecision, _unwrap_tokens



# ----------------------------------------------------------------------
# T5: Supply Chain & Package Lifecycle Security
# ----------------------------------------------------------------------

# Install-class verbs of the JS package managers (npm/pnpm/yarn/bun):
# bare `install`, short `i`, tarball/git-URL forms all land here.
_T5_JS_INSTALL_VERBS = frozenset({"install", "add", "i", "ci", "update", "upgrade"})


def _first_positional(tokens: list[str], start: int = 1):
    """Index of the first non-flag token at/after ``start`` (None when absent)."""
    for i in range(start, len(tokens)):
        if not tokens[i].startswith("-"):
            return i
    return None


def _check_supply_chain(command: str, raw_tokens: list[str]) -> SecurityDecision | None:
    """T5 supply-chain gate.

    Denies installs configured against unencrypted HTTP/git indexes.

    Asks (human confirmation) for auto-confirmed one-shot package execution:
    `npx -y/--yes <pkg>`, `pnpm dlx <pkg>`, `yarn dlx <pkg>` — these fetch and
    run an arbitrary package with no prompt, the exact supply-chain footgun
    T5 exists for.

    TK-51 (user policy 2026-09-05, "always ask"): every agent-driven package
    installation asks — npm/pnpm/yarn/bun install-class verbs (incl. bare
    `install` and bare `yarn` = yarn install), `npm exec -y`, `npm init|create
    <pkg>`, `yarn|pnpm create <pkg>`, `bunx`/`bun x` (bun has no interactive
    install prompt, so the bare-npx rationale below does not apply), `deno
    install|add|run npm:<pkg>`, pip/pip3/`python -m pip install`, `uv pip
    install|add|sync|tool install`, `flutter|dart pub get|add`, `pod install`,
    `dbt deps`. The boundary is the primary command semantics: build commands
    that merely resolve locked dependencies (cargo build, uv run, ./gradlew
    build) stay allow — documented asymmetry (wave-2 plan §7). `install|add
    --dry-run` stays allow: lifecycle scripts are not executed.

    Bare `npx <tool>` WITHOUT -y/--yes is intentionally NOT asked: when the
    package is not installed, npx stops at an interactive install prompt;
    a stalled child is caught by the default hang-policy timeout instead.
    """
    # Substring pre-filter (fast path): extended by TK-51 with the heads of
    # the always-ask install matrix ("bun" covers bunx; "dbt" keeps the dbt
    # deps row of the matrix reachable). Commands without any of these
    # substrings cannot match anything below.
    if "=" not in command and not any(
        h in command
        for h in ("pip", "uv", "npm", "pnpm", "yarn", "python", "npx",
                  "bun", "cargo", "flutter", "pod", "deno", "dart", "dbt")
    ):
        return None

    # Check for prefix environment variable registry overrides (PIP_INDEX_URL=http://, NPM_CONFIG_REGISTRY=http://)
    if "=" in command:
        for raw_tok in raw_tokens:
            if "=" in raw_tok and not raw_tok.startswith("-"):
                var_name, val = raw_tok.split("=", 1)
                var_upper = var_name.upper()
                if any(pkg_var in var_upper for pkg_var in ("PIP_INDEX", "PIP_EXTRA", "NPM_CONFIG_REGISTRY", "YARN_REGISTRY")):
                    val_lower = val.lower()
                    if val_lower.startswith("http://") or val_lower.startswith("git://") or val_lower.startswith("git+http://"):
                        return SecurityDecision(
                            decision="deny",
                            reason="Configuring unencrypted package index via environment variable is prohibited",
                            category="T5_SUPPLY_CHAIN",
                        )

    tokens = _unwrap_tokens(raw_tokens)
    if not tokens:
        return None

    head = os.path.basename(tokens[0])

    # Auto-confirmed one-shot package execution (TK-48, ask-tier): npx with
    # -y/--yes skips the install prompt; pnpm/yarn `dlx` is prompt-free by
    # design. Escalate to "ask" — see the function docstring for the bare
    # `npx <tool>` counterpart (allow path, hang-policy timeout).
    if head == "npx" and any(tok in ("-y", "--yes") for tok in tokens[1:]):
        return SecurityDecision(
            decision="ask",
            reason="npx -y/--yes auto-installs and executes an arbitrary npm package, requiring human confirmation",
            category="T5_SUPPLY_CHAIN",
        )
    if head in ("pnpm", "yarn") and "dlx" in tokens[1:]:
        return SecurityDecision(
            decision="ask",
            reason=f"{head} dlx auto-installs and executes an arbitrary package, requiring human confirmation",
            category="T5_SUPPLY_CHAIN",
        )

    # Insecure pip / uv install over plain HTTP or unencrypted git
    is_pip = (
        head in ("pip", "pip3")
        or head.startswith("python")
        or head == "uv"
    )
    if is_pip:
        if "install" in tokens or "add" in tokens or "ci" in tokens:
            for tok in tokens:
                tok_lower = tok.lower()
                if (
                    tok_lower.startswith("http://")
                    or tok_lower.startswith("git+http://")
                    or tok_lower.startswith("git://")
                    or tok_lower.startswith("git+git://")
                ):
                    return SecurityDecision(
                        decision="deny",
                        reason="Installing packages from unencrypted HTTP/git endpoints is prohibited",
                        category="T5_SUPPLY_CHAIN",
                    )
                if (
                    tok_lower.startswith("--extra-index-url=http://")
                    or tok_lower.startswith("--index-url=http://")
                    or tok_lower.startswith("--default-index=http://")
                    or tok_lower.startswith("--index=http://")
                    or tok_lower.startswith("-i=http://")
                    or tok_lower.startswith("--find-links=http://")
                    or tok_lower.startswith("-f=http://")
                ):
                    return SecurityDecision(
                        decision="deny",
                        reason="Configuring unencrypted HTTP package index is prohibited",
                        category="T5_SUPPLY_CHAIN",
                    )
            for idx, tok in enumerate(tokens):
                if tok in ("--extra-index-url", "--index-url", "--default-index", "--index", "-i", "--find-links", "-f") and idx + 1 < len(tokens):
                    if tokens[idx + 1].lower().startswith("http://") or tokens[idx + 1].lower().startswith("git://"):
                        return SecurityDecision(
                            decision="deny",
                            reason="Configuring unencrypted HTTP package index is prohibited",
                            category="T5_SUPPLY_CHAIN",
                        )

    # Insecure npm/pnpm/yarn install over plain HTTP or unencrypted git
    if head in ("npm", "pnpm", "yarn"):
        if "install" in tokens or "add" in tokens or "i" in tokens or "ci" in tokens or "update" in tokens or head == "yarn":
            for tok in tokens:
                tok_lower = tok.lower()
                if (
                    tok_lower.startswith("http://")
                    or tok_lower.startswith("git+http://")
                    or tok_lower.startswith("git://")
                    or "@http://" in tok_lower
                    or "@git://" in tok_lower
                ):
                    return SecurityDecision(
                        decision="deny",
                        reason="Installing packages from unencrypted HTTP/git endpoints is prohibited",
                        category="T5_SUPPLY_CHAIN",
                    )
                if tok_lower.startswith("--registry=http://") or tok_lower.startswith("-registry=http://"):
                    return SecurityDecision(
                        decision="deny",
                        reason="Configuring unencrypted HTTP package registry is prohibited",
                        category="T5_SUPPLY_CHAIN",
                    )
            for idx, tok in enumerate(tokens):
                if tok in ("--registry", "-registry") and idx + 1 < len(tokens):
                    if tokens[idx + 1].lower().startswith("http://") or tokens[idx + 1].lower().startswith("git://"):
                        return SecurityDecision(
                            decision="deny",
                            reason="Configuring unencrypted HTTP package registry is prohibited",
                            category="T5_SUPPLY_CHAIN",
                        )

    # ------------------------------------------------------------------
    # TK-51 always-ask install matrix (user policy 2026-09-05, variant b):
    # any agent-driven package installation requires human confirmation.
    # The deny scans above run first, so HTTP endpoints keep denying while
    # HTTPS tarballs / git URLs land here as "ask". --dry-run installs do
    # not execute lifecycle scripts and stay allow.
    # ------------------------------------------------------------------
    dry_run = "--dry-run" in tokens[1:]

    # JS package managers: npm / pnpm / yarn / bun
    if head in ("npm", "pnpm", "yarn", "bun"):
        vi = _first_positional(tokens)
        verb = tokens[vi] if vi is not None else None
        rest = tokens[vi + 1:] if vi is not None else []
        has_pkg_arg = _first_positional(tokens, vi + 1) is not None if vi is not None else False

        if verb in _T5_JS_INSTALL_VERBS and not dry_run:
            return SecurityDecision(
                decision="ask",
                reason=f"'{head} {verb}' installs packages from a registry; agent-driven installs always require human confirmation",
                category="T5_SUPPLY_CHAIN",
            )
        if head == "yarn" and vi is None and "--version" not in tokens[1:]:
            # Bare `yarn` (flags-only form included) equals `yarn install`.
            return SecurityDecision(
                decision="ask",
                reason="Bare 'yarn' equals 'yarn install' and installs project packages, requiring human confirmation",
                category="T5_SUPPLY_CHAIN",
            )
        if head == "npm" and verb == "exec" and any(t in ("-y", "--yes") for t in rest):
            return SecurityDecision(
                decision="ask",
                reason="npm exec -y/--yes auto-installs and executes an arbitrary npm package, requiring human confirmation",
                category="T5_SUPPLY_CHAIN",
            )
        if verb in ("init", "create") and head in ("npm", "yarn", "pnpm") and has_pkg_arg:
            return SecurityDecision(
                decision="ask",
                reason=f"'{head} {verb} <pkg>' fetches and executes a create-* package, requiring human confirmation",
                category="T5_SUPPLY_CHAIN",
            )
        if head == "bun" and verb == "x" and has_pkg_arg:
            return SecurityDecision(
                decision="ask",
                reason="'bun x <pkg>' auto-installs and executes an arbitrary package, requiring human confirmation",
                category="T5_SUPPLY_CHAIN",
            )

    # bunx always asks: bun has no interactive install prompt, so the
    # bare-npx allow rationale (hang-policy timeout) does not apply (N-F7e).
    if head == "bunx":
        if _first_positional(tokens) is not None:
            return SecurityDecision(
                decision="ask",
                reason="'bunx <pkg>' auto-installs and executes an arbitrary package without an interactive prompt, requiring human confirmation",
                category="T5_SUPPLY_CHAIN",
            )

    # deno: dependency additions and npm:-scheme one-shot execution
    if head == "deno":
        vi = _first_positional(tokens)
        if vi is not None:
            verb = tokens[vi]
            if verb in ("install", "add"):
                return SecurityDecision(
                    decision="ask",
                    reason=f"'deno {verb}' fetches packages, requiring human confirmation",
                    category="T5_SUPPLY_CHAIN",
                )
            if verb == "run" and any(t.startswith("npm:") for t in tokens[vi + 1:]):
                return SecurityDecision(
                    decision="ask",
                    reason="'deno run npm:<pkg>' fetches and executes an npm package, requiring human confirmation",
                    category="T5_SUPPLY_CHAIN",
                )

    # Python: pip / pip3 / python -m pip (roll-back of the v2.3.0 mutator
    # allow-list; user decision R2 2026-09-05)
    if head in ("pip", "pip3"):
        vi = _first_positional(tokens)
        if vi is not None and tokens[vi] in ("install", "add") and not dry_run:
            return SecurityDecision(
                decision="ask",
                reason="'pip install' installs packages from a registry; agent-driven installs always require human confirmation",
                category="T5_SUPPLY_CHAIN",
            )
    if head.startswith("python") and len(tokens) >= 4 and tokens[1] == "-m" and tokens[2] in ("pip", "pip3"):
        vi = _first_positional(tokens, 3)
        if vi is not None and tokens[vi] in ("install", "add") and not dry_run:
            return SecurityDecision(
                decision="ask",
                reason="'python -m pip install' installs packages from a registry; agent-driven installs always require human confirmation",
                category="T5_SUPPLY_CHAIN",
            )

    # uv: installs/syncs ask; `uv run` stays allow (primary semantics: run)
    if head == "uv":
        vi = _first_positional(tokens)
        if vi is not None:
            verb = tokens[vi]
            wi = _first_positional(tokens, vi + 1)
            is_uv_install = (
                (verb == "pip" and wi is not None and tokens[wi] == "install")
                or (verb == "tool" and wi is not None and tokens[wi] == "install")
                or verb in ("add", "sync")
            )
            if is_uv_install and not dry_run:
                return SecurityDecision(
                    decision="ask",
                    reason="'uv' package installation/sync requires human confirmation",
                    category="T5_SUPPLY_CHAIN",
                )

    # Mobile/Dart toolchains: pub get / pub add fetch dependencies
    if head in ("flutter", "dart"):
        vi = _first_positional(tokens)
        if vi is not None and tokens[vi] == "pub":
            wi = _first_positional(tokens, vi + 1)
            if wi is not None and tokens[wi] in ("get", "add"):
                return SecurityDecision(
                    decision="ask",
                    reason=f"'{head} pub {tokens[wi]}' fetches package dependencies, requiring human confirmation",
                    category="T5_SUPPLY_CHAIN",
                )

    # CocoaPods
    if head == "pod":
        vi = _first_positional(tokens)
        if vi is not None and tokens[vi] == "install":
            return SecurityDecision(
                decision="ask",
                reason="'pod install' fetches CocoaPods dependencies, requiring human confirmation",
                category="T5_SUPPLY_CHAIN",
            )

    # dbt (head itself ships with E5; the matrix row is live from TK-51)
    if head == "dbt":
        vi = _first_positional(tokens)
        if vi is not None and tokens[vi] == "deps":
            return SecurityDecision(
                decision="ask",
                reason="'dbt deps' fetches packages from git/package registries, requiring human confirmation",
                category="T5_SUPPLY_CHAIN",
            )

    return None
