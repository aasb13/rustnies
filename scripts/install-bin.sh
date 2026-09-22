#!/usr/bin/env bash
#
# install-bin.sh — build rustnies and install only the binary.
#
# No systemd units, no config/state directories, no key provisioning. Use
# install.sh for the full setup. Handy for trying rustnies out or for hosts
# where you will run it manually.
#
# Usage:
#   ./scripts/install-bin.sh [OPTIONS]
#
# Options:
#   --prefix <dir>   Install prefix (default: /usr/local). The binary goes to
#                    <prefix>/bin/rustnies. Use --prefix ~/.local for a
#                    user-local install that needs no root.
#   --skip-build     Use the existing target/release/rustnies (no build).
#   --help, -h       Show this help and exit.

set -euo pipefail

PREFIX="/usr/local"
SKIP_BUILD=0

ORIGINAL_ARGS=("$@")

usage() {
  sed -n '3,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)      PREFIX="$2"; shift 2 ;;
    --skip-build)  SKIP_BUILD=1; shift ;;
    -h|--help)     usage ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_SRC="$REPO_ROOT/target/release/rustnies"
DEST_DIR="$PREFIX/bin"
DEST="$DEST_DIR/rustnies"

if [[ $SKIP_BUILD -eq 0 ]]; then
  command -v cargo >/dev/null 2>&1 || die "cargo not found (required to build)"
  log "building rustnies (release) in $REPO_ROOT"
  (cd "$REPO_ROOT" && cargo build --release)
fi

[[ -x "$BIN_SRC" ]] || die "binary not found at $BIN_SRC (run without --skip-build, or build first)"

# Elevate only if the destination is not writable. Pass --skip-build so the
# elevated run reuses the binary just built above (as the invoking user) instead
# of rebuilding under sudo, where secure_path would hide ~/.cargo/bin.
if [[ ! -w "$DEST_DIR" ]] && [[ ! -w "$(dirname "$DEST_DIR")" ]]; then
  if [[ $EUID -ne 0 ]]; then
    warn "$DEST_DIR is not writable; re-running with sudo"
    exec sudo "$0" --skip-build "${ORIGINAL_ARGS[@]}"
  fi
fi

log "installing binary to $DEST"
install -d "$DEST_DIR" || die "could not create $DEST_DIR"
install -m 0755 "$BIN_SRC" "$DEST"

echo
log "done. rustnies is at $DEST"
echo "  Make sure it is on your PATH (it is at $DEST_DIR)."
echo "  The server/client subcommands need root for TUN/NAT on Linux:"
echo "    sudo rustnies keygen --key /var/lib/rustnies/server.key"
echo "    sudo rustnies server  --key /var/lib/rustnies/server.key"
echo "  For the full systemd setup, run scripts/install.sh instead."

# vim: set ft=bash: