#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Smoke test of a built ThreatCull image. Needs Docker and curl, no internet.
# Usage: scripts/docker-smoke.sh [image]   (default: threatcull:ci)
set -euo pipefail

image="${1:-threatcull:ci}"
name="threatcull-smoke-$$"
volume="threatcull-smoke-$$"
port=16969
base="http://127.0.0.1:${port}"

cleanup() {
  echo "--- container logs ---"
  docker logs "$name" 2>&1 || true
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

start() {
  docker run -d --name "$name" -p "127.0.0.1:${port}:6969" -v "${volume}:/data" \
    -e THREATCULL_ADMIN_PASSWORD=smoke-password-123 "$@" "$image" >/dev/null
}

wait_healthy() {
  for _ in $(seq 60); do
    if curl -fsS "${base}/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "FAIL: /healthz never answered" >&2
  return 1
}

check() { echo "ok: $1"; }

start
wait_healthy && check "healthz answers"

[ "$(docker exec "$name" id -u)" = "10001" ] && check "runs as uid 10001"
docker exec "$name" threatcull --data-dir /data user list | grep -q '^admin' && check "admin created"
docker exec "$name" threatcull --data-dir /data outputs list | grep -q 'ip-high' \
  && check "default Outputs exist"

code=$(curl -s -o /dev/null -w '%{http_code}' "${base}/o/ip-high?token=wrong")
[ "$code" = "404" ] && check "wrong Feed Token is a 404"
code=$(curl -s -o /dev/null -w '%{http_code}' "${base}/")
[ "$code" = "303" ] && check "dashboard redirects to login"

if docker logs "$name" 2>&1 | grep -Eq '[A-Za-z0-9_-]{43}'; then
  echo "FAIL: a token-shaped string reached the container log" >&2
  exit 1
fi
check "no token in the log"

docker exec "$name" threatcull --data-dir /data config export | grep -q '^threatcull_config: 1' \
  && check "config export works"

docker restart "$name" >/dev/null
wait_healthy && check "healthy after a restart"
docker exec "$name" threatcull --data-dir /data user list | grep -q '^admin' \
  && check "data persisted on the volume"

docker rm -f "$name" >/dev/null
start --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true
wait_healthy && check "runs with a read-only root filesystem and no capabilities"

echo "smoke test passed"
