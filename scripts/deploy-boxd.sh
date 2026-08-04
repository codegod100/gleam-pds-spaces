#!/usr/bin/env bash
# Deploy this checkout on the pds boxd VM.
#
# Intended to run ON the VM after git has been synced to the target SHA:
#   bash scripts/deploy-boxd.sh
#   bash scripts/deploy-boxd.sh --skip-deps   # source-only: skip gleam deps download
#
# Wired from boxd's deploy-on-push platform (/etc/boxd-platform.conf):
#   RELOAD_CMD='bash scripts/deploy-boxd.sh --skip-deps'
#   REBUILD_CMD='bash scripts/deploy-boxd.sh'
#   REBUILD_PATHS='gleam.toml manifest.toml'
set -euo pipefail

export PATH="${HOME}/.local/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"

# Non-interactive boxd exec shells often lack a user systemd session.
if [ -z "${XDG_RUNTIME_DIR:-}" ] && [ -d "/run/user/$(id -u)" ]; then
  export XDG_RUNTIME_DIR="/run/user/$(id -u)"
fi
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] && [ -n "${XDG_RUNTIME_DIR:-}" ] \
  && [ -S "${XDG_RUNTIME_DIR}/bus" ]; then
  export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SKIP_DEPS=0
for arg in "$@"; do
  case "$arg" in
    --skip-deps) SKIP_DEPS=1 ;;
    -h | --help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
  esac
done

echo "[deploy] root=${ROOT} sha=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"

if ! command -v gleam >/dev/null 2>&1; then
  echo "[deploy] error: gleam not on PATH" >&2
  exit 1
fi

if [ "$SKIP_DEPS" -eq 0 ]; then
  echo "[deploy] gleam deps download ..."
  gleam deps download
else
  echo "[deploy] skipping gleam deps download (--skip-deps)"
fi

echo "[deploy] gleam build ..."
gleam build

restart_systemd_unit() {
  local unit=$1
  if systemctl cat "$unit" >/dev/null 2>&1; then
    echo "[deploy] restarting system unit ${unit} ..."
    sudo systemctl restart "$unit"
    sudo systemctl --no-pager --full status "$unit" | head -n 20 || true
    return 0
  fi
  if systemctl --user cat "$unit" >/dev/null 2>&1; then
    echo "[deploy] restarting user unit ${unit} ..."
    systemctl --user restart "$unit"
    systemctl --user --no-pager --full status "$unit" | head -n 20 || true
    return 0
  fi
  return 1
}

if restart_systemd_unit gleam-pds.service \
  || restart_systemd_unit gleam-pds \
  || restart_systemd_unit gleam_pds.service; then
  echo "[deploy] done (systemd)"
  exit 0
fi

if command -v pm2 >/dev/null 2>&1 && pm2 describe gleam-pds >/dev/null 2>&1; then
  echo "[deploy] restarting pm2 app gleam-pds ..."
  pm2 restart gleam-pds
  echo "[deploy] done (pm2)"
  exit 0
fi

if [ -f docker-compose.yml ] || [ -f compose.yml ] || [ -f compose.yaml ]; then
  echo "[deploy] docker compose up -d --build ..."
  docker compose up -d --build
  echo "[deploy] done (compose)"
  exit 0
fi

echo "[deploy] error: no gleam-pds systemd unit, pm2 app, or compose file found to restart" >&2
echo "[deploy] built successfully; start the service manually, then re-run." >&2
exit 1
