#!/usr/bin/env bash
#
# End-to-end multi-node check, run inside the compose `client` service.
#
# It joins the revika DHT through the seed node (SEED_ADDR), stores a random
# test file so the pipeline spreads its erasure-coded shards across the
# discovered storage nodes, then asserts three things:
#
#   1. put succeeds and writes a manifest (the read-capability),
#   2. EVERY node's on-disk shard store gained shards (the node data volumes are
#      bind-mounted read-only under /nodes/<name>, so we can count them),
#   3. get reconstructs a file byte-identical to the original.
#
# Exit status is 0 only if all three hold, so `docker compose up` surfaces a
# failure as a non-zero client exit.
set -euo pipefail

: "${SEED_ADDR:?SEED_ADDR must point at the seed node /p2p multiaddr}"

# Node data volumes, mounted read-only by compose. Each is a revika DiskStore
# root; its shards live under <mount>/shards/<xx>/<hash>.
NODE_MOUNTS=(/nodes/seed /nodes/node2 /nodes/node3)

WORK=/tmp/revika-verify
mkdir -p "$WORK"
SRC="$WORK/testfile.bin"
OUT="$WORK/roundtrip.bin"
MANIFEST="$WORK/testfile.rvk.json"

# A 1 MiB random payload: one 4 MiB-max chunk => k=4 data + m=2 parity = 6
# shards, which round-robin across 3 nodes as 2 shards each.
echo ">> generating 1 MiB random test file"
head -c 1048576 /dev/urandom >"$SRC"

count_shards() { find "$1/shards" -type f 2>/dev/null | wc -l | tr -d ' '; }

echo ">> shard counts BEFORE put:"
declare -A before
for m in "${NODE_MOUNTS[@]}"; do
  before[$m]=$(count_shards "$m")
  echo "     $m: ${before[$m]}"
done

# DHT discovery is eventually consistent (advertise records + routing tables
# converge asynchronously), so give put a few attempts before failing.
echo ">> put via bootstrap $SEED_ADDR"
put_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl put -bootstrap "$SEED_ADDR" -manifest "$MANIFEST" "$SRC"; then
    put_ok=1
    break
  fi
  echo "   put attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$put_ok" ] || { echo "FAIL: put never succeeded"; exit 1; }
[ -s "$MANIFEST" ] || { echo "FAIL: no manifest written"; exit 1; }

echo ">> shard counts AFTER put:"
total_new=0
missing=""
for m in "${NODE_MOUNTS[@]}"; do
  now=$(count_shards "$m")
  delta=$((now - before[$m]))
  total_new=$((total_new + delta))
  echo "     $m: $now  (+$delta)"
  [ "$delta" -gt 0 ] || missing="$missing $m"
done

if [ -n "$missing" ]; then
  echo "FAIL: these nodes received no shards:$missing"
  exit 1
fi
echo "OK: all ${#NODE_MOUNTS[@]} nodes received shards ($total_new total)"

echo ">> get via bootstrap $SEED_ADDR"
get_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl get -bootstrap "$SEED_ADDR" -manifest "$MANIFEST" -o "$OUT"; then
    get_ok=1
    break
  fi
  echo "   get attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$get_ok" ] || { echo "FAIL: get never succeeded"; exit 1; }

if cmp -s "$SRC" "$OUT"; then
  echo "OK: retrieved file is byte-identical to the original"
else
  echo "FAIL: retrieved file differs from the original"
  exit 1
fi

echo
echo "PASS: data was spread across all nodes and retrieved intact."
