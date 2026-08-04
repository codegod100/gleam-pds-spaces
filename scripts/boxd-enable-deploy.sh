#!/usr/bin/env bash
# One-time: enable boxd deploy-on-push for this repo on the pds golden VM.
#
# Prerequisites:
#   - boxd CLI installed and authenticated (`boxd auth`)
#   - golden VM named `pds` already running the app (boxd-setup-golden)
#   - gh can register webhooks on the repo (admin/maintain), or pass
#     GH_TOKEN_INIT as a fine-grained PAT with Webhooks read+write
#
# Usage (from your laptop, not CI):
#   bash scripts/boxd-enable-deploy.sh
#   GH_TOKEN_INIT=ghp_… bash scripts/boxd-enable-deploy.sh
set -euo pipefail

export PATH="${HOME}/.local/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"

VM=${BOXD_VM:-pds}
REPO_DIR=${REPO_DIR:-/home/boxd/gleam-pds-spaces}
DEFAULT_BRANCH=${DEFAULT_BRANCH:-main}
APP_PORT=${APP_PORT:-8000}
ORIGIN_URL=${ORIGIN_URL:-https://github.com/codegod100/gleam-pds-spaces.git}

# Gleam always recompiles on source changes; --skip-deps is the hot path.
RELOAD_CMD=${RELOAD_CMD:-'bash scripts/deploy-boxd.sh --skip-deps'}
REBUILD_CMD=${REBUILD_CMD:-'bash scripts/deploy-boxd.sh'}
REBUILD_PATHS=${REBUILD_PATHS:-'gleam.toml manifest.toml'}
UP_CMD=${UP_CMD:-'sudo systemctl start gleam-pds'}
HEALTH_PATH=${HEALTH_PATH:-/xrpc/_health}

if ! command -v boxd >/dev/null 2>&1; then
  echo "error: boxd CLI not found. Install: curl -fsSL https://boxd.sh/downloads/install.sh | sh" >&2
  exit 1
fi

echo "[enable-deploy] vm=${VM} repo_dir=${REPO_DIR} branch=${DEFAULT_BRANCH}"

# Ensure the on-VM deploy script is present at HEAD of the default branch
# after the next sync; for first enable we also copy it up if missing.
boxd machine exec "$VM" -- test -f "$REPO_DIR/scripts/deploy-boxd.sh" \
  || boxd machine cp scripts/deploy-boxd.sh "$VM:$REPO_DIR/scripts/deploy-boxd.sh"

EXTRA_ENV=()
if [ -n "${GH_TOKEN_INIT:-}" ]; then
  EXTRA_ENV+=(-e "GH_TOKEN_INIT=${GH_TOKEN_INIT}")
fi

boxd machine exec "$VM" \
  -e "ORIGIN_URL=${ORIGIN_URL}" \
  -e "REPO_DIR=${REPO_DIR}" \
  -e "DEFAULT_BRANCH=${DEFAULT_BRANCH}" \
  -e "APP_PORT=${APP_PORT}" \
  -e "HEALTH_PATH=${HEALTH_PATH}" \
  -e "UP_CMD=${UP_CMD}" \
  -e "RELOAD_CMD=${RELOAD_CMD}" \
  -e "REBUILD_CMD=${REBUILD_CMD}" \
  -e "REBUILD_PATHS=${REBUILD_PATHS}" \
  "${EXTRA_ENV[@]}" \
  -- bash /opt/boxd-platform/enable-deploy.sh

echo
echo "[enable-deploy] verify: curl -sS -o /dev/null -w '%{http_code}\\n' https://hooks.${VM}.boxd.sh/hooks/deploy"
echo "[enable-deploy] logs:   boxd machine exec ${VM} -- sudo tail -f /var/log/golden-deploy.log"
