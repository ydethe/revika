#!/usr/bin/env bash
#
# Delete-protection check, run inside the compose `deleter` service.
#
# revika's authorization model: a shard is owned by whoever stored it, proven by
# a token signed with their Ed25519 signing key. A node only drops a caller's
# OWN ownership claim on DELETE, and frees a shard's bytes only once its last
# owner deletes. So possessing the read-capability (a copy of the root pointer)
# lets you READ a file but must NOT let you delete it — delete authority is the
# signing key, not the read-cap. `rm` enforces this: it refuses to advance a root
# owned by a different identity, and a node independently refuses a DELETE token
# from a non-owner.
#
# This script proves that end to end against the live multi-node network. It is
# self-contained: an "owner" stores a file, then
#
#   1. NEGATIVE — a DIFFERENT user ("mallory") who holds a copy of the owner's
#      root pointer (the read-cap) but not the owner's signing key tries to rm the
#      file. It must be refused, and the file must still be retrievable.
#   2. POSITIVE — the owner rm's with their own signing key. It must succeed,
#      and the file must then be unrecoverable (its shards are gone).
#
# The positive control matters: without it, a bug that made *every* rm fail
# would masquerade as "protected". Exit status is 0 only if both hold.

# NOTE: not `set -e` — we deliberately run commands we expect to fail and then
# inspect their exit status.
set -uo pipefail

: "${SEED_ADDR:?SEED_ADDR must point at the seed node /p2p multiaddr}"

WORK=/tmp/revika-delete
mkdir -p "$WORK"
SRC="$WORK/secret.bin"
OUT="$WORK/roundtrip.bin"
# Each user drives its own workspace whose config.json carries the bootstrap peer
# (bootstrap is no longer a per-command flag). The root pointer is <ws>/root.json.
OWNER_WS="$WORK/owner-ws"
MALLORY_WS="$WORK/mallory-ws"
OWNER_ROOT="$OWNER_WS/root.json"       # the owner's signed namespace anchor
MALLORY_ROOT="$MALLORY_WS/root.json"   # a copy mallory obtained (the read-cap)

fail=0

# DHT discovery + provider records are eventually consistent, so allow a few
# attempts before giving up on the operations we expect to SUCCEED.
retry() {
  local what="$1"; shift
  local n
  for n in 1 2 3 4 5 6; do
    if "$@"; then return 0; fi
    echo "   $what attempt $n failed; retrying in 5s..."
    sleep 5
  done
  return 1
}

# Two independent User identities, each with its own signing key. Only `owner`
# will store the file; `mallory` is a legitimate other user (e.g. someone the
# file was shared with) who must not be able to delete it.
revika-ctl keygen -key "$WORK/owner"   -pow-difficulty 0 >/dev/null
revika-ctl keygen -key "$WORK/mallory" -pow-difficulty 0 >/dev/null

# A workspace per user, each bootstrapped through the seed.
revika-ctl connect -root "$OWNER_WS"   -bootstrap "$SEED_ADDR" >/dev/null
revika-ctl connect -root "$MALLORY_WS" -bootstrap "$SEED_ADDR" >/dev/null

echo ">> owner stores a 1 MiB file across the nodes"
head -c 1048576 /dev/urandom >"$SRC"
retry "store" revika-ctl cp -root "$OWNER_WS" -signkey "$WORK/owner.sign.key" "$SRC" rvk:secret.bin \
  || { echo "FAIL: owner store never succeeded"; exit 1; }
[ -s "$OWNER_ROOT" ] || { echo "FAIL: no root pointer written"; exit 1; }

# Mallory somehow obtained a copy of the owner's root pointer (the read-cap): she
# can READ the file, but her signing key does not own its shards.
cp "$OWNER_ROOT" "$MALLORY_ROOT"

echo
echo "== delete-protection checks =="

# 1) NEGATIVE: mallory holds a copy of the owner's root (the read-cap) but signs
#    with her OWN key, so she owns no shard. `rm` must refuse to advance a root
#    owned by another identity (and a node independently refuses her DELETE
#    token), and the file must survive.
echo ">> attempt: a non-owner (with the read-cap) removes the file — MUST be denied"
if revika-ctl rm -root "$MALLORY_WS" -signkey "$WORK/mallory.sign.key" rvk:secret.bin; then
  echo "   FAIL: a non-owner removed another user's file"
  fail=1
else
  echo "   OK: denied — a non-owner cannot remove the file"
fi

echo ">> the file must still be retrievable after the refused removal"
if retry "get" revika-ctl cp -root "$OWNER_WS" rvk:secret.bin "$OUT" && cmp -s "$SRC" "$OUT"; then
  echo "   OK: the file is intact — the unauthorized removal changed nothing"
else
  echo "   FAIL: the file is gone or altered after a removal that should have been refused"
  fail=1
fi

# 2) POSITIVE control: the owner rm's with their signing key. It must succeed,
#    and the file must then be unrecoverable.
echo ">> attempt: the owner removes the file — MUST succeed"
if revika-ctl rm -root "$OWNER_WS" -signkey "$WORK/owner.sign.key" rvk:secret.bin; then
  echo "   OK: the owner removed their own file"
else
  echo "   FAIL: the owner could not remove their own file"
  fail=1
fi

echo ">> the file must no longer be retrievable after the owner's removal"
# A single attempt: the file is grafted out of the root and its blobs removed
# synchronously when the last owner deletes, so a retrieval can no longer resolve
# the path (or gather k shards) and must fail.
if revika-ctl cp -root "$OWNER_WS" rvk:secret.bin "$WORK/gone.bin" 2>/dev/null; then
  echo "   FAIL: retrieved the file after the owner removed it"
  fail=1
else
  echo "   OK: the file is unrecoverable after removal"
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "PASS: only the owner can remove — an unauthorized rm was refused, the owner's succeeded."
  exit 0
fi
echo "FAIL: delete protection did not hold."
exit 1
