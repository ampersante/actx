#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
usage: bash install.sh [--help]
Installs actx into ~/.local/bin and runs `actx init` by default.
Skip init with: ACTX_INIT=0 bash install.sh
EOF
  exit 0
fi

PYTHON="${PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "error: $PYTHON not found" >&2
  exit 1
fi

version="$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [[ "$version" != "3.14" ]]; then
  echo "error: python 3.14 required, found $version" >&2
  echo "install it with: brew install python@3.14" >&2
  exit 1
fi

src="$(cd "$(dirname "$0")" && pwd)"
bin_dir="${HOME}/.local/bin"
mkdir -p "$bin_dir"
link="$bin_dir/actx"

if [[ -L "$link" ]]; then
  target="$(readlink "$link")"
  if [[ "$target" != "$src/actx" ]]; then
    rm -f "$link"
    ln -s "$src/actx" "$link"
  fi
elif [[ -e "$link" ]]; then
  echo "error: $link exists and is not a symlink" >&2
  exit 1
else
  ln -s "$src/actx" "$link"
fi

chmod +x "$src/actx"

case ":$PATH:" in
  *":$bin_dir:"*) ;;
  *)
    echo "warning: $bin_dir is not on PATH" >&2
    echo "add it: echo 'export PATH=\"$HOME/.local/bin:\$PATH\"' >> ~/.zshrc" >&2
    ;;
esac

if [[ "${ACTX_INIT:-1}" == "1" ]]; then
  "$link" init
fi

echo "actx installed: $link"
cat <<'EOF'
Next steps:
  1. Ensure ~/.local/bin is on PATH, then restart your terminal.
  2. Run `actx init` again if no agent was detected above.
  3. Codex: approve the hook via /hooks. Cursor: insert the printed section in UI.
EOF
