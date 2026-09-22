#!/usr/bin/env bash
#
# uninstall.sh — remove rustnies.
#
# By default this stops/disables the services, removes the systemd units and
# the installed binary, but KEEPS your config and keys. Pass --purge to also
# delete /etc/rustnies, /var/lib/rustnies (keys!) and /run/rustnies.
#
# Usage:
#   sudo ./scripts/uninstall.sh [OPTIONS]
#
# Options:
#   --prefix <dir>   Prefix the binary was installed to (default: /usr/local).
#   --root <dir>     DESTDIR-style staging root the installer used. Live
#                    systemd calls are skipped (only files under <root> are
#                    removed); no root is needed.
#   --keep-binary    Do not remove the binary.
#   --purge          Also delete config and keys (cannot be undone).
#   --help, -h       Show this help and exit.

set -euo pipefail

PREFIX="/usr/local"
ROOT=""
KEEP_BINARY=0
PURGE=0

ORIGINAL_ARGS=("$@")

usage() {
  sed -n '3,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)       PREFIX="$2"; shift 2 ;;
    --root)         ROOT="$2"; shift 2 ;;
    --keep-binary)  KEEP_BINARY=1; shift ;;
    --purge)        PURGE=1; shift ;;
    -h|--help)      usage ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

if [[ $EUID -ne 0 ]] && [[ -z "$ROOT" ]]; then
  warn "uninstall needs root; re-running with sudo"
  exec sudo "$0" "${ORIGINAL_ARGS[@]}"
fi

BIN_DST="$ROOT$PREFIX/bin/rustnies"
CONF_DIR="$ROOT/etc/rustnies"
STATE_DIR="$ROOT/var/lib/rustnies"
RUN_DIR="$ROOT/run/rustnies"
UNIT_DIR="$ROOT/etc/systemd/system"

# --- services ----------------------------------------------------------------

if [[ -z "$ROOT" ]] && command -v systemctl >/dev/null 2>&1; then
  for unit in rustnies-server rustnies-client; do
    if [[ -f "$UNIT_DIR/$unit.service" ]] || systemctl list-unit-files 2>/dev/null | grep -q "^$unit.service"; then
      log "stopping and disabling $unit"
      systemctl disable --now "$unit" >/dev/null 2>&1 || true
    fi
  done
fi

for unit in rustnies-server rustnies-client; do
  rm -f "$UNIT_DIR/$unit.service"
done

if [[ -z "$ROOT" ]] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

# --- binary ------------------------------------------------------------------

if [[ $KEEP_BINARY -eq 0 ]] && [[ -e "$BIN_DST" ]]; then
  log "removing binary $BIN_DST"
  rm -f "$BIN_DST"
fi

# --- config / keys / runtime -------------------------------------------------

if [[ $PURGE -eq 1 ]]; then
  warn "--purge: deleting config and keys"
  rm -rf "$CONF_DIR" "$STATE_DIR" "$RUN_DIR"
  log "removed $CONF_DIR, $STATE_DIR, $RUN_DIR"
else
  log "kept $CONF_DIR (config) and $STATE_DIR (keys); pass --purge to delete them"
fi

echo
log "rustnies uninstalled"
if [[ $PURGE -eq 0 ]]; then
  echo "  configs/keys retained at $CONF_DIR and $STATE_DIR"
fi

# vim: set ft=bash: