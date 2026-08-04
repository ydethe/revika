#!/usr/bin/env bash
#
# Delete-protection check, run inside the compose `deleter` service.
#
# revika's authorization model: a shard is owned by whoever stored it, proven by
# a token signed with their Ed25519 signing key. A node only drops a caller's
# OWN ownership claim on DELETE, and frees a shard's bytes only once its last
# owner deletes. So possessing the read-capability (the manifest) lets you READ
# a file but must NOT let you DELETE it — delete authority is the signing key,
# not the read-cap.
#
# This script proves that end to end against the live multi-node network. It is
# self-contained: an "owner" stores a file, then
#
#   1. NEGATIVE — a DIFFERENT user ("mallory") who holds the manifest (the
#      read-cap) but not the owner's signing key tries to delete every shard.
#      The node must refuse, and the file must still be retrievable.
#   2. POSITIVE — the owner deletes with their own signing key. It must succeed,
#      and the file must then be unrecoverable (its shards are gone).
#
# The positive control matters: without it, a bug that made *every* delete fail
# would masquerade as "protected". Exit status is 0 only if both hold.

# NOTE: not `set -e` — we deliberately run commands we expect to fail and then
# inspect their exit status.
set -uo pipefail

: "${SEED_ADDR:?SEED_ADDR must point at the seed node /p2p multiaddr}"

WORK=/tmp/revika-delete
mkdir -p "$WORK"
SRC="$WORK/secret.bin"
OUT="$WORK/roundtrip.bin"
MANIFEST="$WORK/secret.rvk.json"

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

echo ">> owner stores a 1 MiB file across the nodes"
head -c 1048576 /dev/urandom >"$SRC"
retry "put" revika-ctl put -bootstrap "$SEED_ADDR" -signkey "$WORK/owner.sign.key" -manifest "$MANIFEST" "$SRC" \
  || { echo "FAIL: owner put never succeeded"; exit 1; }
[ -s "$MANIFEST" ] || { echo "FAIL: no manifest written"; exit 1; }

echo
echo "== delete-protection checks =="

# 1) NEGATIVE: mallory has the manifest (the read-cap) but signs with her OWN
#    key, so she is not an owner of any shard. Every shard delete must be
#    refused (the command exits non-zero), and the file must survive.
echo ">> attempt: a non-owner (with the read-cap) deletes the file — MUST be denied"
if revika-ctl delete -bootstrap "$SEED_ADDR" -signkey "$WORK/mallory.sign.key" -manifest "$MANIFEST"; then
  echo "   FAIL: a non-owner deleted another user's shards"
  fail=1
else
  echo "   OK: denied — a non-owner cannot delete the shards"
fi

echo ">> the file must still be retrievable after the refused delete"
if retry "get" revika-ctl get -bootstrap "$SEED_ADDR" -manifest "$MANIFEST" -o "$OUT" && cmp -s "$SRC" "$OUT"; then
  echo "   OK: the file is intact — the unauthorized delete changed nothing"
else
  echo "   FAIL: the file is gone or altered after a delete that should have been refused"
  fail=1
fi

# 2) POSITIVE control: the owner deletes with their signing key. It must succeed,
#    and the file must then be unrecoverable.
echo ">> attempt: the owner deletes the file — MUST succeed"
if revika-ctl delete -bootstrap "$SEED_ADDR" -signkey "$WORK/owner.sign.key" -manifest "$MANIFEST"; then
  echo "   OK: the owner deleted their own shards"
else
  echo "   FAIL: the owner could not delete their own shards"
  fail=1
fi

echo ">> the file must no longer be retrievable after the owner's delete"
# A single attempt: the blobs are removed synchronously when the last owner
# deletes, so a get can no longer gather k shards and must fail.
if revika-ctl get -bootstrap "$SEED_ADDR" -manifest "$MANIFEST" -o "$WORK/gone.bin" 2>/dev/null; then
  echo "   FAIL: retrieved the file after the owner deleted it"
  fail=1
else
  echo "   OK: the file is unrecoverable after deletion"
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "PASS: only the owner can delete — an unauthorized delete was refused, the owner's succeeded."
  exit 0
fi
echo "FAIL: delete protection did not hold."
exit 1
