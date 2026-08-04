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
#   5. `share -path` carves a SINGLE file out of the stored tree, wrapped to a
#      recipient's key, and `get -cap` reconstructs just that file (§3.5) —
#      proving you can share one file from a tree without re-uploading it.
#   6. `share -path` on a SUBDIRECTORY wraps that subtree cap, and `get -cap`
#      restores only that subtree — nothing outside the shared path leaks.
#   7. `sync` materializes the namespace as 0-byte placeholders fetching ONLY
#      directory blobs (no file content), then `hydrate` pulls content for one
#      file (leaving the rest placeholders) and finally for the whole tree —
#      the on-demand hydration model of §3.8.
#
# Exit status is 0 only if all seven hold, so a compose run surfaces a failure as
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

# --- share a SINGLE file out of the stored tree (Architecture §3.5) ----------
# The tree is already stored and spread across the nodes; nothing is re-uploaded.
# We resolve one file's cap through the DHT, wrap it to a fresh recipient key,
# and reconstruct just that file from the -cap.
echo
echo ">> generating a recipient identity to share to"
revika-ctl keygen -key "$WORK/recipient" -pow-difficulty 0 >/dev/null
RCPT_PUB="$WORK/recipient.pub"
RCPT_KEY="$WORK/recipient.key"

SHARE_REL="docs/a.txt"
FILE_CAP="$WORK/a.cap"
FILE_OUT="$WORK/a.out"
echo ">> share -path $SHARE_REL (wrap one file from the tree)"
share_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl share -bootstrap "$SEED_ADDR" -manifest "$ROOTCAP" \
      -path "$SHARE_REL" -to "@$RCPT_PUB" -o "$FILE_CAP"; then
    share_ok=1
    break
  fi
  echo "   share attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$share_ok" ] || { echo "FAIL: share -path (file) never succeeded"; exit 1; }
[ -s "$FILE_CAP" ] || { echo "FAIL: no file cap written"; exit 1; }

echo ">> get -cap (reconstruct the single shared file)"
get_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl get -bootstrap "$SEED_ADDR" -cap "$FILE_CAP" -key "$RCPT_KEY" -o "$FILE_OUT"; then
    get_ok=1
    break
  fi
  echo "   get attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$get_ok" ] || { echo "FAIL: get -cap (file) never succeeded"; exit 1; }
if ! cmp -s "$SRC/$SHARE_REL" "$FILE_OUT"; then
  echo "FAIL: shared single file $SHARE_REL differs from the original"
  exit 1
fi
echo "OK: a single file was shared from the tree and reconstructed byte-identically"

# --- share a SUBDIRECTORY out of the stored tree -----------------------------
SHARE_DIR="docs"
DIR_CAP="$WORK/docs.cap"
DIR_OUT="$WORK/docs.out"
echo ">> share -path $SHARE_DIR (wrap a subtree from the tree)"
share_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl share -bootstrap "$SEED_ADDR" -manifest "$ROOTCAP" \
      -path "$SHARE_DIR" -to "@$RCPT_PUB" -o "$DIR_CAP"; then
    share_ok=1
    break
  fi
  echo "   share attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$share_ok" ] || { echo "FAIL: share -path (subtree) never succeeded"; exit 1; }

echo ">> get -cap -o (restore only the shared subtree)"
get_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl get -bootstrap "$SEED_ADDR" -cap "$DIR_CAP" -key "$RCPT_KEY" -o "$DIR_OUT"; then
    get_ok=1
    break
  fi
  echo "   get attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$get_ok" ] || { echo "FAIL: get -cap (subtree) never succeeded"; exit 1; }

# The subtree is rooted at DIR_OUT: docs/a.txt appears as a.txt (no "docs/").
if ! cmp -s "$SRC/$SHARE_DIR/a.txt" "$DIR_OUT/a.txt"; then
  echo "FAIL: shared subtree file a.txt differs from the original"
  exit 1
fi
if ! cmp -s "$SRC/$SHARE_DIR/nested/big.bin" "$DIR_OUT/nested/big.bin"; then
  echo "FAIL: shared subtree file nested/big.bin differs from the original"
  exit 1
fi
# Nothing outside the shared path may leak: root.txt lived above docs/.
if [ -e "$DIR_OUT/root.txt" ]; then
  echo "FAIL: shared subtree leaked root.txt from outside the shared path"
  exit 1
fi
echo "OK: a subtree was shared from the tree and restored, leaking nothing outside it"

# --- lazy sync + on-demand hydrate (Architecture §3.8) -----------------------
# `sync` materializes the namespace fetching ONLY directory blobs — every file is
# a 0-byte placeholder. `hydrate` then pulls content for just the wanted paths.
SYNC="$WORK/synced"
echo
echo ">> sync (materialize the namespace, no file content) into $SYNC"
sync_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl sync -bootstrap "$SEED_ADDR" -manifest "$ROOTCAP" -o "$SYNC"; then
    sync_ok=1
    break
  fi
  echo "   sync attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$sync_ok" ] || { echo "FAIL: sync never succeeded"; exit 1; }

# The namespace must exist, with the index and 0-byte placeholders (big.bin is
# ~1 MiB in the original, so a nonzero placeholder would mean content leaked in).
[ -f "$SYNC/.revika-sync.json" ] || { echo "FAIL: sync wrote no index"; exit 1; }
for rel in root.txt docs/a.txt docs/nested/big.bin; do
  [ -f "$SYNC/$rel" ] || { echo "FAIL: placeholder $rel missing after sync"; exit 1; }
  sz=$(wc -c <"$SYNC/$rel" | tr -d ' ')
  [ "$sz" = "0" ] || { echo "FAIL: placeholder $rel is $sz bytes, want 0 (content must not be synced)"; exit 1; }
done
[ -d "$SYNC/empty" ] || { echo "FAIL: empty directory not recreated by sync"; exit 1; }
echo "OK: sync recreated the namespace as 0-byte placeholders (no file content fetched)"

echo ">> hydrate a single file (docs/a.txt)"
hyd_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl hydrate -bootstrap "$SEED_ADDR" -C "$SYNC" docs/a.txt; then
    hyd_ok=1
    break
  fi
  echo "   hydrate attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$hyd_ok" ] || { echo "FAIL: hydrate (single file) never succeeded"; exit 1; }
cmp -s "$SRC/docs/a.txt" "$SYNC/docs/a.txt" || { echo "FAIL: hydrated docs/a.txt differs"; exit 1; }
# The other files must still be un-hydrated placeholders.
sz=$(wc -c <"$SYNC/docs/nested/big.bin" | tr -d ' ')
[ "$sz" = "0" ] || { echo "FAIL: hydrating one file also fetched big.bin ($sz bytes)"; exit 1; }
echo "OK: only the requested file was hydrated; the rest stayed placeholders"

echo ">> hydrate the whole tree (-C with no path)"
hyd_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl hydrate -bootstrap "$SEED_ADDR" -C "$SYNC"; then
    hyd_ok=1
    break
  fi
  echo "   hydrate attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$hyd_ok" ] || { echo "FAIL: hydrate (whole tree) never succeeded"; exit 1; }
while IFS= read -r rel; do
  [ -n "$rel" ] || continue
  if ! cmp -s "$SRC/$rel" "$SYNC/$rel"; then
    echo "FAIL: hydrated $rel differs from the original"
    exit 1
  fi
done <<<"$src_files"
echo "OK: hydrating the whole tree reproduced every file byte-identically"

echo
echo "PASS: a directory tree was spread across all nodes, restored intact, shared"
echo "      out of (single files and subtrees) end-to-end encrypted, and lazily"
echo "      synced then hydrated on demand."
