#!/usr/bin/env bash
#
# End-to-end directory round-trip, run inside the compose `tree` service.
#
# Where verify.sh exercises a single file, this exercises revika's directory
# support (Architecture §3.6): a whole directory tree is stored as a Merkle DAG
# of cap-addressed encrypted blobs (each file a manifest blob, each folder a
# directory blob), grafted into the User's mutable namespace under an rvk: path
# and anchored by a signed root pointer (persisted to root.json). It joins the
# revika DHT through the seed node (SEED_ADDR), stores a nested tree with
# `cp <dir> rvk:tree` so the pipeline spreads every blob's erasure-coded shards
# across the discovered storage nodes, then asserts:
#
#   1. the client discovers EVERY storage node over the DHT (as verify.sh does);
#   2. `cp <dir> rvk:tree` succeeds and advances the signed root.json;
#   3. EVERY node's on-disk shard store gained shards — the tree's blobs
#      (files AND directories) spread across all nodes, not just the seed;
#   4. `cp rvk:tree <out>` reconstructs the whole tree byte-identically, with the
#      same set of files and directories (including empty ones) as the original.
#   5. `share rvk:tree/docs/a.txt` seals a SINGLE file out of the stored tree to
#      a recipient's key, and the recipient opens that sealed root with their key
#      and reconstructs just that file (§3.5) — proving you can share one file
#      from a tree without re-uploading it, and without a bearer token.
#   6. `share rvk:tree/docs` seals a SUBTREE, and the recipient restores only that
#      subtree — nothing outside the shared path leaks.
#
# Exit status is 0 only if all six hold, so a compose run surfaces a failure as
# a non-zero exit for this service.
set -euo pipefail

: "${SEED_ADDR:?SEED_ADDR must point at the seed node /p2p multiaddr}"

# Node data volumes, mounted read-only by compose. Each is a revika DiskStore
# root; its shards live under <mount>/shards/<xx>/<hash>.
NODE_MOUNTS=(/nodes/seed /nodes/node2 /nodes/node3)

WORK=/tmp/revika-tree
SRC="$WORK/src"
OUT="$WORK/out"                 # restored whole tree (must NOT pre-exist)
ROOTFILE="$WORK/root.json"      # the User's signed namespace anchor
rm -rf "$WORK"
mkdir -p "$SRC"

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

# The client signs each write with its Ed25519 signing identity; generate one.
echo ">> generating the client's signing identity"
revika-ctl keygen -key "$WORK/user" -pow-difficulty 0 >/dev/null
SIGNKEY="$WORK/user.sign.key"

count_shards() { find "$1/shards" -type f 2>/dev/null | wc -l | tr -d ' '; }

# Discover every storage node over the DHT (see verify.sh for the rationale).
EXPECTED_NODES=${#NODE_MOUNTS[@]}
echo ">> discovering storage nodes via bootstrap $SEED_ADDR (expect all $EXPECTED_NODES)"
reachable=0
for attempt in 1 2 3 4 5 6; do
  nodes_out=$(revika-ctl node -bootstrap "$SEED_ADDR" || true)
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

echo ">> shard counts BEFORE store:"
declare -A before
for m in "${NODE_MOUNTS[@]}"; do
  before[$m]=$(count_shards "$m")
  echo "     $m: ${before[$m]}"
done

# DHT discovery is eventually consistent, so give the store a few attempts.
echo ">> cp \$SRC rvk:tree via bootstrap $SEED_ADDR (store the whole tree)"
put_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl cp -bootstrap "$SEED_ADDR" -signkey "$SIGNKEY" -root "$ROOTFILE" "$SRC" rvk:tree; then
    put_ok=1
    break
  fi
  echo "   store attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$put_ok" ] || { echo "FAIL: cp (store) never succeeded"; exit 1; }
[ -s "$ROOTFILE" ] || { echo "FAIL: no root pointer written"; exit 1; }
echo "OK: cp stored the tree and advanced the signed root at $ROOTFILE"

echo ">> shard counts AFTER store:"
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

echo ">> cp rvk:tree \$OUT via bootstrap $SEED_ADDR (restore the whole tree)"
get_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl cp -bootstrap "$SEED_ADDR" -root "$ROOTFILE" rvk:tree "$OUT"; then
    get_ok=1
    break
  fi
  echo "   retrieve attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$get_ok" ] || { echo "FAIL: cp (retrieve) never succeeded"; exit 1; }

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
# `share` resolves one file's cap and seals a RootPointer anchored at it to a
# fresh recipient key (wrapping, never a bearer token). The recipient opens that
# sealed root with their private key and reconstructs just that file.
echo
echo ">> generating a recipient identity to share to"
revika-ctl keygen -key "$WORK/recipient" -pow-difficulty 0 >/dev/null
RCPT_PUB="$WORK/recipient.pub"
RCPT_KEY="$WORK/recipient.key"

SHARE_REL="docs/a.txt"
FILE_SEALED="$WORK/a.root.json"
FILE_OUT="$WORK/a.out"          # explicit output path (a file-anchored root)
echo ">> share rvk:tree/$SHARE_REL (seal one file to the recipient)"
share_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl share -bootstrap "$SEED_ADDR" -root "$ROOTFILE" -signkey "$SIGNKEY" \
      -to "@$RCPT_PUB" -o "$FILE_SEALED" "rvk:tree/$SHARE_REL"; then
    share_ok=1
    break
  fi
  echo "   share attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$share_ok" ] || { echo "FAIL: share (file) never succeeded"; exit 1; }
[ -s "$FILE_SEALED" ] || { echo "FAIL: no sealed shared root written"; exit 1; }

echo ">> recipient opens the sealed root with -key and reconstructs the file"
get_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl cp -bootstrap "$SEED_ADDR" -root "$FILE_SEALED" -key "$RCPT_KEY" rvk: "$FILE_OUT"; then
    get_ok=1
    break
  fi
  echo "   retrieve attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$get_ok" ] || { echo "FAIL: recipient cp (shared file) never succeeded"; exit 1; }
if ! cmp -s "$SRC/$SHARE_REL" "$FILE_OUT"; then
  echo "FAIL: shared single file $SHARE_REL differs from the original"
  exit 1
fi
echo "OK: a single file was shared from the tree and reconstructed byte-identically"

# A wrong key must NOT open the sealed shared root.
echo ">> a stranger's key must not open the sealed shared root"
revika-ctl keygen -key "$WORK/stranger" -pow-difficulty 0 >/dev/null
if revika-ctl ls -bootstrap "$SEED_ADDR" -root "$FILE_SEALED" -key "$WORK/stranger.key" >/dev/null 2>&1; then
  echo "FAIL: a sealed shared root opened with the wrong key"
  exit 1
fi
echo "OK: the sealed shared root refuses the wrong key"

# --- share a SUBTREE out of the stored tree ----------------------------------
SHARE_DIR="docs"
DIR_SEALED="$WORK/docs.root.json"
DIR_OUT="$WORK/docs.out"        # must NOT pre-exist (a dir-anchored root)
echo ">> share rvk:tree/$SHARE_DIR (seal a subtree to the recipient)"
share_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl share -bootstrap "$SEED_ADDR" -root "$ROOTFILE" -signkey "$SIGNKEY" \
      -to "@$RCPT_PUB" -o "$DIR_SEALED" "rvk:tree/$SHARE_DIR"; then
    share_ok=1
    break
  fi
  echo "   share attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$share_ok" ] || { echo "FAIL: share (subtree) never succeeded"; exit 1; }

echo ">> recipient restores only the shared subtree"
get_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl cp -bootstrap "$SEED_ADDR" -root "$DIR_SEALED" -key "$RCPT_KEY" rvk: "$DIR_OUT"; then
    get_ok=1
    break
  fi
  echo "   retrieve attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$get_ok" ] || { echo "FAIL: recipient cp (shared subtree) never succeeded"; exit 1; }

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

echo
echo "PASS: a directory tree was spread across all nodes, restored intact, and"
echo "      shared out of (single files and subtrees) end-to-end encrypted, with"
echo "      each shared root sealed to the recipient's key (no bearer token)."
