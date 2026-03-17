#!/usr/bin/env bash
# deploy.sh — build and deploy rexnet to root@178.104.4.222
# Usage: ./deploy.sh

set -euo pipefail

SERVER="root@178.104.4.222"
REMOTE_BIN="/usr/local/bin/rexnet"
SERVICE="rexnet"

echo "==> Building release binary..."
cargo build --release

BINARY="$(cargo metadata --no-deps --format-version 1 \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['target_directory'])")/release/rexnet"

echo "==> Binary: $BINARY ($(du -sh "$BINARY" | cut -f1))"

echo "==> Stopping service on server..."
ssh "$SERVER" "systemctl stop $SERVICE || true"

echo "==> Uploading binary..."
scp "$BINARY" "$SERVER:$REMOTE_BIN"

echo "==> Starting service..."
ssh "$SERVER" "systemctl start $SERVICE"

echo "==> Waiting for service to be healthy..."
sleep 2
ssh "$SERVER" "systemctl is-active $SERVICE"

echo "==> Smoke test..."
STATUS=$(curl -so /dev/null -w "%{http_code}" https://rexnet.horobets.dev)
if [ "$STATUS" = "200" ]; then
  echo "==> OK — https://rexnet.horobets.dev returned HTTP $STATUS"
else
  echo "ERROR: https://rexnet.horobets.dev returned HTTP $STATUS" >&2
  ssh "$SERVER" "journalctl -u $SERVICE -n 20 --no-pager" >&2
  exit 1
fi

echo ""
echo "Deploy complete."
