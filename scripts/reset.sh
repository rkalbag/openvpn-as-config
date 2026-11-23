#!/usr/bin/env bash
# Stop both Access Server containers, wipe ./data, start fresh, and wait
# until `sacli status` reports every service on in each container.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null || export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"

docker compose down --remove-orphans >/dev/null 2>&1 || true
rm -rf ./data
docker compose up -d

wait_ready() {
  local name=$1 i
  for i in $(seq 1 120); do
    # ready = sacli answers and every entry in service_status is "on"
    if docker exec "$name" sacli status 2>/dev/null | python3 -c '
import json, sys
s = json.load(sys.stdin)["service_status"]
sys.exit(0 if s and all(v == "on" for v in s.values()) else 1)' 2>/dev/null; then
      echo "$name ready"; return 0
    fi
    sleep 2
  done
  echo "$name not ready after 240s" >&2
  docker logs --tail 50 "$name" >&2
  return 1
}
for c in ${CONTAINERS:-as-src as-tgt}; do wait_ready "$c"; done
