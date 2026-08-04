#!/usr/bin/env bash
#
# End-to-end directory round-trip, run inside the compose `tree` service.
#
# Where verify.sh exercises a single file, this exercises revika's directory
# support (Architecture §3.6): a whole directory tree is stored as a Merkle DAG
# of cap-addressed encrypted blobs (each file a manifest blob, each folder a
# directory blob), anchored by the root directory's read-capability. It joins
# the revika DHT through the seed node (SEED_ADDR), stores a nested tree with
# `put -r` so the pipeline spreads every blob's erasure-coded shards across the
# discovered storage nodes, then asserts:
#
#   1. the client discovers EVERY storage node over the DHT (as verify.sh does);
#   2. `put -r` succeeds and writes a root cap (the tree's read-capability);
#   3. EVERY node's on-disk shard store gained shards — the tree's blobs
#      (files AND directories) spread across all nodes, not just the seed;
#   4. `get -r` reconstructs the whole tree byte-identically, with the same set
#      of files and directories (including empty ones) as the original.
#
# Exit status is 0 only if all four hold, so a compose run surfaces a failure as
# a non-zero exit for this service.
set -euo pipefail

: "${SEED_ADDR:?SEED_ADDR must point at the seed node /p2p multiaddr}"

# Node data volumes, mounted read-only by compose. Each is a revika DiskStore
# root; its shards live under <mount>/shards/<xx>/<hash>.
NODE_MOUNTS=(/nodes/seed /nodes/node2 /nodes/node3)

WORK=/tmp/revika-tree
SRC="$WORK/src"
OUT="$WORK/out"
ROOTCAP="$WORK/tree.rvk.json"
rm -rf "$WORK"
mkdir -p "$SRC" "$OUT"

# A distinctive plaintext canary embedded in one of the files. Nodes must hold
# only ciphertext, so it must never appear verbatim in any raw shard.
MARKER="REVIKA-PLAINTEXT-CANARY-DO-NOT-LEAK-cf83e1357eefb8bd"

# Build a nested source tree:
#   src/root.txt                  (small, canary)
#   src/docs/a.txt                (small)
#   src/docs/nested/big.bin       (~1 MiB random => multi-shard blob)
#   src/empty/                    (an empty directory — must survive)
echo ">> building a nested source tree under $SRC"
mkdir -p "$SRC/docs/nested" "$SRC/empty"
printf '%s\n' "$MARKER" >"$SRC/root.txt"
printf 'document a\n' >"$SRC/docs/a.txt"
head -c 1048576 /dev/urandom >"$SRC/docs/nested/big.bin"

# The client signs each PUT with its Ed25519 signing identity; generate one.
echo ">> generating the client's signing identity"
revika-ctl keygen -key "$WORK/user" -pow-difficulty 0 >/dev/null
SIGNKEY="$WORK/user.sign.key"

count_shards() { find "$1/shards" -type f 2>/dev/null | wc -l | tr -d ' '; }

# Discover every storage node over the DHT (see verify.sh for the rationale).
EXPECTED_NODES=${#NODE_MOUNTS[@]}
echo ">> discovering storage nodes via bootstrap $SEED_ADDR (expect all $EXPECTED_NODES)"
reachable=0
for attempt in 1 2 3 4 5 6; do
  nodes_out=$(revika-ctl nodes -bootstrap "$SEED_ADDR" || true)
  printf '%s\n' "$nodes_out" | sed 's/^/     /'
  reachable=$(printf '%s\n' "$nodes_out" | sed -n 's/.*(\([0-9]*\) reachable).*/\1/p')
  reachable=${reachable:-0}
  if [ "$reachable" -ge "$EXPECTED_NODES" ]; then
    break
  fi
  echo "   reached $reachable of $EXPECTED_NODES; retrying in 5s..."
  sleep 5
done
if [ "$reachable" -lt "$EXPECTED_NODES" ]; then
  echo "FAIL: client reached only $reachable of $EXPECTED_NODES storage nodes over the DHT"
  exit 1
fi
echo "OK: client discovered and reached all $EXPECTED_NODES storage nodes via the DHT"

echo ">> shard counts BEFORE put:"
declare -A before
for m in "${NODE_MOUNTS[@]}"; do
  before[$m]=$(count_shards "$m")
  echo "     $m: ${before[$m]}"
done

# DHT discovery is eventually consistent, so give `put -r` a few attempts.
echo ">> put -r via bootstrap $SEED_ADDR (store the whole tree)"
put_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl put -r -bootstrap "$SEED_ADDR" -signkey "$SIGNKEY" -manifest "$ROOTCAP" "$SRC"; then
    put_ok=1
    break
  fi
  echo "   put attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$put_ok" ] || { echo "FAIL: put -r never succeeded"; exit 1; }
[ -s "$ROOTCAP" ] || { echo "FAIL: no root cap written"; exit 1; }
echo "OK: put -r wrote the tree's root cap to $ROOTCAP"

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

echo ">> get -r via bootstrap $SEED_ADDR (restore the whole tree)"
get_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl get -r -bootstrap "$SEED_ADDR" -manifest "$ROOTCAP" -o "$OUT"; then
    get_ok=1
    break
  fi
  echo "   get attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$get_ok" ] || { echo "FAIL: get -r never succeeded"; exit 1; }

# Compare the trees. debian-slim has coreutils (find, cmp) but not necessarily
# `diff -r`, so compare structurally: same set of files, and every file byte-
# identical. Paths are compared relative to each tree root.
echo ">> comparing restored tree $OUT against original $SRC"
src_files=$( (cd "$SRC" && find . -type f | sort) )
out_files=$( (cd "$OUT" && find . -type f | sort) )
if [ "$src_files" != "$out_files" ]; then
  echo "FAIL: file sets differ"
  echo "--- original ---"; printf '%s\n' "$src_files"
  echo "--- restored ---"; printf '%s\n' "$out_files"
  exit 1
fi
while IFS= read -r rel; do
  [ -n "$rel" ] || continue
  if ! cmp -s "$SRC/$rel" "$OUT/$rel"; then
    echo "FAIL: restored $rel differs from the original"
    exit 1
  fi
done <<<"$src_files"
echo "OK: every restored file is byte-identical to the original"

# Directories, including the empty one, must survive the round-trip.
src_dirs=$( (cd "$SRC" && find . -type d | sort) )
out_dirs=$( (cd "$OUT" && find . -type d | sort) )
if [ "$src_dirs" != "$out_dirs" ]; then
  echo "FAIL: directory sets differ (an empty directory may have been dropped)"
  echo "--- original ---"; printf '%s\n' "$src_dirs"
  echo "--- restored ---"; printf '%s\n' "$out_dirs"
  exit 1
fi
echo "OK: directory structure (including empty dirs) preserved"

echo
echo "PASS: a directory tree was spread across all nodes and restored intact."
