#!/usr/bin/env bash
#
# Node-down resilience scenario: store a file across all three nodes, take one
# node DOWN, then retrieve the file successfully from the survivors.
#
# It demonstrates revika's durability guarantee end to end. A file is encoded as
# k=4 data + m=2 parity = 6 shards, spread round-robin 2-per-node across the 3
# nodes. Stopping one node makes its 2 shards unreachable (its provider records
# go stale), yet the remaining 4 shards — exactly k — still reconstruct the file.
#
# This runs on the HOST (not in a container) because it needs to stop a node
# between the store and retrieve steps. It drives docker compose directly:
#
#   ./deploy/resilience.sh              # takes node3 down
#   DOWN_NODE=node2 ./deploy/resilience.sh
#
# Exit code is 0 only if the file is retrieved intact with a node down.
set -uo pipefail
cd "$(dirname "$0")/.."

# docker compose needs SEED_ADDR for variable substitution; template.env carries
# the value matching the committed dev seed key (deploy/seed.key).
[ -f .env ] || cp template.env .env

# The node to take down. Must NOT be `seed`: the client bootstraps through the
# seed, so stopping it would break DHT access rather than test shard durability.
DOWN_NODE="${DOWN_NODE:-node3}"
if [ "$DOWN_NODE" = "seed" ]; then
  echo "refusing to down the seed node (clients bootstrap through it); pick node2 or node3" >&2
  exit 2
fi

code=1
cleanup() {
  echo ">> tearing down"
  docker compose down -v >/dev/null 2>&1
  exit "$code"
}
trap cleanup EXIT INT TERM

echo ">> [1/4] building images and starting the 3-node network"
docker compose up -d --build seed node2 node3 || exit 1

echo ">> [2/4] storing a file (6 shards round-robin => 2 per node)"
docker compose run --rm --build store || { echo "store step failed"; exit 1; }

echo ">> [3/4] taking $DOWN_NODE DOWN (its 2 shards become unreachable)"
docker compose stop "$DOWN_NODE" || exit 1

echo ">> [4/4] retrieving with $DOWN_NODE down (needs only k=4 of 6 shards)"
if docker compose run --rm retrieve; then
  code=0
  echo ">> SUCCESS: data survived a node outage"
else
  code=1
  echo ">> FAILURE: could not retrieve with a node down"
fi
