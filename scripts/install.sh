#!/usr/bin/env bash
#
# install.sh — full rustnies installer.
#
# Builds the release binary, installs it, creates the config / state / runtime
# directories, writes stock config files, provisions static keypairs, and
# installs (and optionally enables) systemd services for the server and/or
# client. For a binary-only install, use install-bin.sh instead.
#
# Usage:
#   sudo ./scripts/install.sh (--server-only | --client-only | --both) [OPTIONS]
#
#   A host runs either the server or the client, never both (both share
#   /run/rustnies/rustnies.sock by default). The role flag is required.
#   --both exists only for single-host loopback testing or a relay that
#   uplinks as a client while serving clients; override ipc_path for one
#   side if you run both.
#
# Options:
#   --server-only         Install only the rustnies-server service.
#   --client-only         Install only the rustnies-client service.
#   --both                Install both services (testing / relay only).
#   --prefix <dir>        Install prefix (default: /usr/local). The binary
#                         goes to <prefix>/bin/rustnies.
#   --root <dir>          DESTDIR-style staging root. All system paths are
#                         prefixed with it (<root>/etc/rustnies, <root>/var/lib,
#                         etc.) and live systemd calls are skipped, so no root
#                         is needed. Useful for packaging / chroots / testing.
#   --no-systemd          Do not install or touch systemd units.
#   --enable              Enable the installed service(s) to start on boot.
#   --start               Enable and start the installed service(s) now.
#   --skip-build          Use the existing target/release/rustnies (no build).
#   --help, -h            Show this help and exit.

set -euo pipefail

PREFIX="/usr/local"
ROOT=""
ROLE=""                # server | client | both (required; no default)
SYSTEMD=1
ENABLE=0
START=0
SKIP_BUILD=0

ORIGINAL_ARGS=("$@")

usage() {
  sed -n '3,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)        PREFIX="$2"; shift 2 ;;
    --root)          ROOT="$2"; shift 2 ;;
    --server-only)   ROLE="server"; shift ;;
    --client-only)   ROLE="client"; shift ;;
    --both)          ROLE="both"; shift ;;
    --no-systemd)    SYSTEMD=0; shift ;;
    --enable)        ENABLE=1; shift ;;
    --start)         START=1; ENABLE=1; shift ;;
    --skip-build)    SKIP_BUILD=1; shift ;;
    -h|--help)       usage ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$ROLE" ]]; then
  echo "missing role: pass --server-only, --client-only, or --both (testing / relay only)" >&2
  exit 2
fi

case "$ROLE" in
  server|client|both) ;;
  *) echo "invalid role (use --server-only, --client-only, or --both)" >&2; exit 2 ;;
esac

# --- helpers -----------------------------------------------------------------

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

if [[ "$ROLE" == "both" ]]; then
  warn "installing both services: a host normally runs either the server or the client"
  warn "(both share /run/rustnies/rustnies.sock by default — override ipc_path for one side)"
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 not found (required for this step)"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$SCRIPT_DIR/dist"
BIN_SRC="$REPO_ROOT/target/release/rustnies"

BIN_DST="$ROOT$PREFIX/bin/rustnies"
CONF_DIR="$ROOT/etc/rustnies"
STATE_DIR="$ROOT/var/lib/rustnies"
RUN_DIR="$ROOT/run/rustnies"
UNIT_DIR="$ROOT/etc/systemd/system"

[[ -d "$DIST_DIR" ]] || die "dist templates not found at $DIST_DIR (run from the repo root)"

# --- build -------------------------------------------------------------------
#
# Build BEFORE elevating to root. cargo lives in the invoking user's PATH
# (e.g. ~/.cargo/bin), which sudo's secure_path hides once we re-exec; building
# as the user also keeps target/ user-owned so later non-root builds don't hit
# permission errors. The elevated re-exec below passes --skip-build to reuse
# this binary instead of rebuilding under sudo.

if [[ $SKIP_BUILD -eq 0 ]]; then
  need_cmd cargo
  log "building rustnies (release) in $REPO_ROOT"
  (cd "$REPO_ROOT" && cargo build --release)
fi

[[ -x "$BIN_SRC" ]] || die "binary not found at $BIN_SRC (run without --skip-build, or build first)"

# --- root --------------------------------------------------------------------
# A real system install (no --root) needs root. A staging install under --root
# does not. Re-exec through sudo with the original flags plus --skip-build (the
# arg loop above has already consumed $@, so re-run with the saved copy); the
# build above already ran as the invoking user, so the elevated run reuses it
# and never needs cargo on its own (secure_path-safe) PATH.

if [[ $EUID -ne 0 ]] && [[ -z "$ROOT" ]]; then
  warn "this installer writes to /etc, /var/lib, /run and the systemd dir; re-running with sudo"
  exec sudo "$0" --skip-build "${ORIGINAL_ARGS[@]}"
fi

# --- binary ------------------------------------------------------------------

log "installing binary to $BIN_DST"
install -d "$(dirname "$BIN_DST")"
install -m 0755 "$BIN_SRC" "$BIN_DST"

# --- directories -------------------------------------------------------------

log "creating directories"
install -d -m 0755 "$CONF_DIR"
install -d -m 0700 "$STATE_DIR"
install -d -m 0755 "$RUN_DIR"

# --- config templates --------------------------------------------------------
#
# Always refresh the *.toml.dist stock copy (safe to overwrite). Write the live
# *.toml only if it does not already exist, so user edits are never clobbered.

install_config() {
  local name="$1"
  install -m 0644 "$DIST_DIR/$name.toml" "$CONF_DIR/$name.toml.dist"
  if [[ ! -e "$CONF_DIR/$name.toml" ]]; then
    cp "$CONF_DIR/$name.toml.dist" "$CONF_DIR/$name.toml"
    chmod 0644 "$CONF_DIR/$name.toml"
    log "wrote $CONF_DIR/$name.toml (edit before starting the service)"
  else
    log "kept existing $CONF_DIR/$name.toml (stock template refreshed at *.toml.dist)"
  fi
}

case "$ROLE" in
  server|both) install_config server ;;
esac
case "$ROLE" in
  client|both) install_config client ;;
esac

# --- keys --------------------------------------------------------------------

log "provisioning static keypairs"
SERVER_PUB=""
case "$ROLE" in
  server|both)
    SERVER_PUB="$("$BIN_DST" keygen --key "$STATE_DIR/server.key")"
    chmod 0600 "$STATE_DIR/server.key"
    log "server public key: $SERVER_PUB"
    ;;
esac
case "$ROLE" in
  client|both)
    CLIENT_PUB="$("$BIN_DST" keygen --key "$STATE_DIR/client.key")"
    chmod 0600 "$STATE_DIR/client.key"
    log "client public key: $CLIENT_PUB"
    ;;
esac

# --- runtime helpers ---------------------------------------------------------

if [[ -z "$ROOT" ]]; then
  log "runtime helper commands (daemon socket under $RUN_DIR):"
  echo "    sudo rustnies status --socket $RUN_DIR/rustnies.sock"
  echo "    sudo rustnies stop   --socket $RUN_DIR/rustnies.sock"
fi

# --- systemd -----------------------------------------------------------------

write_unit() {
  local name="$1"
  local unit="rustnies-$name.service"
  install -d "$UNIT_DIR"
  sed "s|__PREFIX__|$PREFIX|g" "$DIST_DIR/$unit" > "$UNIT_DIR/$unit"
  chmod 0644 "$UNIT_DIR/$unit"
}

enable_start_unit() {
  local name="$1"
  local unit="rustnies-$name.service"
  if [[ $START -eq 1 ]]; then
    if [[ "$name" == "client" && -f "$CONF_DIR/client.toml" ]] \
       && grep -q 'REPLACE_WITH_SERVER_PUBKEY_HEX' "$CONF_DIR/client.toml"; then
      warn "not starting rustnies-client: server_key in $CONF_DIR/client.toml is still the placeholder"
      warn "edit it (use the server's public key printed above) then: systemctl start rustnies-client"
      systemctl enable "$unit" >/dev/null 2>&1 || true
    else
      systemctl enable --now "$unit" >/dev/null 2>&1 || warn "enable/start of $unit failed (check: systemctl status $unit)"
      log "enabled and started $unit"
    fi
  elif [[ $ENABLE -eq 1 ]]; then
    systemctl enable "$unit" >/dev/null 2>&1 || warn "enable of $unit failed"
    log "enabled $unit (start with: systemctl start $unit)"
  else
    log "$unit installed (enable with: systemctl enable --now $unit)"
  fi
}

if [[ $SYSTEMD -eq 1 ]]; then
  if [[ -n "$ROOT" ]]; then
    # Staging install: write the unit files into the root tree but do not talk
    # to the live service manager (it cannot see a staging root).
    log "staging systemd units into $UNIT_DIR (enable/start on the target system)"
    case "$ROLE" in
      server|both) write_unit server ;;
    esac
    case "$ROLE" in
      client|both) write_unit client ;;
    esac
  elif command -v systemctl >/dev/null 2>&1 && [[ -d "$UNIT_DIR" ]]; then
    case "$ROLE" in
      server|both) write_unit server; systemctl daemon-reload; enable_start_unit server ;;
    esac
    case "$ROLE" in
      client|both) write_unit client; systemctl daemon-reload; enable_start_unit client ;;
    esac
  else
    warn "systemd not detected; skipping unit install (--no-systemd hides this)"
  fi
fi

# --- summary -----------------------------------------------------------------

echo
log "rustnies installed"
echo "  binary:  $BIN_DST"
echo "  config:  $CONF_DIR/{server,client}.toml"
echo "  keys:    $STATE_DIR/{server,client}.key  (mode 0600)"
if [[ -z "$ROOT" ]]; then
  echo "  socket:  $RUN_DIR/rustnies.sock"
else
  echo "  socket:  $RUN_DIR/rustnies.sock  (staging root: $ROOT)"
fi
if [[ $SYSTEMD -eq 1 ]]; then
  echo "  units:   $UNIT_DIR/rustnies-{server,client}.service"
fi
if [[ -n "$SERVER_PUB" ]]; then
  echo
  echo "  Server public key (give this to clients for server_key):"
  echo "    $SERVER_PUB"
fi
echo
if [[ -z "$ROOT" ]]; then
  echo "  Next: edit $CONF_DIR/client.toml and set server/server_key, then"
  echo "        sudo systemctl enable --now rustnies-server rustnies-client"
  warn "ensure 'iptables' and 'ip' (iproute2) are installed; the daemon shells out to them."
fi

# vim: set ft=bash: