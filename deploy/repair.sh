#!/usr/bin/env bash
#
# Autonomous node-side repair scenario: store a file across the nodes, take one
# node DOWN, and prove a *surviving* node regenerates the downed node's shards
# onto a node that lacked them — with NO client online — then retrieve the file.
#
# This is the payoff for issue #3. It differs from resilience.sh (which only
# proves a file survives a node outage from the k surviving shards): here we prove
# redundancy is actively RESTORED. Each stored shard carries a stripe descriptor
# (K/M + sibling IDs, no key) and a User-signed repair grant; a survivor's repair
# loop probes the stripe over the DHT, sees it degraded, and re-places the missing
# shards under the grant with no owner key on the node.
#
# It runs on the HOST (not in a container) because it stops a node mid-scenario.
# The node repair cadence is shortened via REPAIR_INTERVAL so a cycle runs inside
# the test window (nodes read -repair-interval=${REPAIR_INTERVAL:-1h}).
#
#   ./deploy/repair.sh                 # takes node3 down
#   DOWN_NODE=node2 ./deploy/repair.sh
#
# Exit code is 0 only if a survivor regenerated a lost shard AND the file is
# retrieved intact.
set -uo pipefail
cd "$(dirname "$0")/.."

# docker compose needs SEED_ADDR for variable substitution; template.env carries
# the value matching the committed dev seed key (deploy/seed.key).
[ -f .env ] || cp template.env .env

DOWN_NODE="${DOWN_NODE:-node3}"
if [ "$DOWN_NODE" = "seed" ]; then
  echo "refusing to down the seed node (clients bootstrap through it); pick node2 or node3" >&2
  exit 2
fi
export DOWN_NODE
export REPAIR_INTERVAL="${REPAIR_INTERVAL:-15s}"

code=1
cleanup() {
  echo ">> tearing down"
  docker compose --profile repair down -v >/dev/null 2>&1
  exit "$code"
}
trap cleanup EXIT INT TERM

echo ">> [1/6] building images and starting the 3-node network (repair-interval=$REPAIR_INTERVAL)"
docker compose up -d --build seed node2 node3 || exit 1

echo ">> [2/6] storing a file across the nodes (each shard carries a stripe descriptor + grant)"
docker compose run --rm --build repair-pre store || { echo "store step failed"; exit 1; }

echo ">> [3/6] snapshotting each node's shard set (the pre-failure baseline)"
docker compose run --rm repair-pre snapshot || { echo "snapshot step failed"; exit 1; }

echo ">> [4/6] taking $DOWN_NODE DOWN (its shards become unreachable)"
docker compose stop "$DOWN_NODE" || exit 1

WAIT="${WAIT:-45}"
echo ">> [5/6] waiting ${WAIT}s for a surviving node to detect and repair the degraded stripe"
sleep "$WAIT"

echo ">> [6/6] verifying a lost shard was regenerated onto a survivor, then retrieving"
if docker compose run --rm repair-post verify && docker compose run --rm repair-post get; then
  code=0
  echo ">> SUCCESS: a survivor autonomously regenerated the lost shards; file intact"
else
  code=1
  echo ">> FAILURE: repair did not re-place the lost shards (or retrieval failed)"
fi
