#!/usr/bin/env sh
#
# PrufGate installer: puts a `prufgate` launcher for this checkout on your PATH.
# Linux, macOS and WSL2. Needs python3 (or Docker for `prufgate --docker`).
#
# Usage:
#   ./install.sh
#

set -eu

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║        PRUFGATE — Verification & Security Engine Installer         ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# 1. Platform Detection
OS="$(uname -s)"
ARCH="$(uname -m)"

IS_WSL=false
if [ -f /proc/version ] && grep -qi "microsoft" /proc/version; then
  IS_WSL=true
fi

PLATFORM_DESC="${OS} (${ARCH})"
if [ "$IS_WSL" = true ]; then
  PLATFORM_DESC="${PLATFORM_DESC} [WSL2]"
fi
echo "✔ Detected platform: ${PLATFORM_DESC}"

# 2. Determine target install directory
TARGET_DIR="${INSTALL_DIR:-}"
if [ -z "${TARGET_DIR}" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    TARGET_DIR="/usr/local/bin"
  elif [ -w "/usr/local/bin" ]; then
    TARGET_DIR="/usr/local/bin"
  else
    TARGET_DIR="${HOME}/.local/bin"
  fi
fi

mkdir -p "${TARGET_DIR}"
TARGET_BIN="${TARGET_DIR}/prufgate"

# 3. Install a launcher that runs this checkout's bin/prufgate. bin/prufgate needs
# the engine next to it, so the checkout must stay where it is. (`pip install .`
# from the checkout is the alternative that needs no checkout at run time.)
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo "")"
if [ -z "${SCRIPT_DIR}" ] || [ ! -f "${SCRIPT_DIR}/bin/prufgate" ] || [ ! -f "${SCRIPT_DIR}/prufgate/cli.py" ]; then
  echo "Error: run install.sh from a PrufGate checkout (bin/prufgate and prufgate/ not found next to it)." >&2
  exit 1
fi
case "${SCRIPT_DIR}" in
  *"'"*) echo "Error: the checkout path contains a single quote; move it to a plain path first." >&2; exit 1 ;;
esac
echo "Installing a PrufGate launcher for ${SCRIPT_DIR} at ${TARGET_BIN}..."
printf '#!/usr/bin/env sh\nPRUFGATE_DIR=%s exec %s "$@"\n' "'${SCRIPT_DIR}'" "'${SCRIPT_DIR}/bin/prufgate'" > "${TARGET_BIN}"

chmod +x "${TARGET_BIN}"
echo "✔ Installed the PrufGate launcher at ${TARGET_BIN}"

# 4. PATH Verification
case ":${PATH}:" in
  *":${TARGET_DIR}:"*) ;;
  *)
    echo ""
    echo "⚠ Notice: ${TARGET_DIR} is not in your \$PATH."
    echo "  Add the following line to your ~/.bashrc, ~/.zshrc, or ~/.profile:"
    echo "    export PATH=\"${TARGET_DIR}:\$PATH\""
    ;;
esac

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  PrufGate installed successfully!"
echo "  Run 'prufgate --help' to get started."
echo "════════════════════════════════════════════════════════════════════"
