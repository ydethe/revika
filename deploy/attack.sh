#!/usr/bin/env bash
#
# Unauthorized-access check, run inside the compose `attacker` service as a
# SEPARATE client from the one that stored the data.
#
# revika's trust model: nodes are dumb, untrusted blob stores
# that hold only encrypted, erasure-coded, content-addressed shards, and they
# serve those shards to ANYONE on the network. Confidentiality therefore rests
# entirely on the read-capability — the decryption keys + shard IDs kept in the
# manifest — which never leaves the storing user's machine.
#
# So an attacker can freely fetch ciphertext shards and read every node's disk;
# what it must NOT be able to do is turn any of that into plaintext. This script
# plays exactly such an attacker, holding what a real adversary could plausibly
# get, and asserts it is denied on every path:
#
#   1. no capability at all              -> cannot even attempt a retrieval,
#   2. a cap wrapped for a THIRD party   -> will not unwrap with the attacker's
#                                           own key (the NaCl-box sharing boundary),
#   3. full read access to node shards   -> the plaintext canary is nowhere in
#                                           them (nodes store only ciphertext).
#
# Each attempt MUST fail; the script exits 0 only if ALL were correctly denied,
# so a leak surfaces as a non-zero attacker exit.

# NOTE: not `set -e` — we deliberately run commands we expect to fail and then
# inspect their exit status.
set -uo pipefail

: "${SEED_ADDR:?SEED_ADDR must point at the seed node /p2p multiaddr}"

# Node data volumes, mounted read-only. A real node operator (or anyone who
# compromises one) sees exactly this: the on-disk shard store.
NODE_MOUNTS=(/nodes/seed /nodes/node2 /nodes/node3)

WORK=/tmp/revika-attack
mkdir -p "$WORK"
OUT="$WORK/stolen.bin"

fail=0

# This attacker is its own client with its own fresh identity, unrelated to the
# user who stored the data or the third party the cap was shared with.
revika-ctl keygen -key "$WORK/attacker" >/dev/null

echo "== unauthorized-access checks (every attempt MUST be denied) =="

# 1) No capability at all. Without a manifest or a cap there are no shard IDs and
#    no keys to work from, so the client cannot even mount a retrieval — network
#    access alone buys nothing.
echo ">> attempt 1: get with no manifest and no cap"
if revika-ctl get -bootstrap "$SEED_ADDR" -o "$OUT" 2>/dev/null; then
  echo "   FAIL: retrieved data with no read-capability whatsoever"
  fail=1
else
  echo "   OK: denied — no read-capability, nothing to retrieve"
fi

# 2) Someone else's cap. The stored manifest was wrapped (NaCl box) for a third
#    party's public key. Unwrapping it with the attacker's own private key must
#    fail — this is the sharing/authorization boundary.
echo ">> attempt 2: unwrap a cap wrapped for another user, using our own key"
if [ -f /handoff/secret.cap ]; then
  if revika-ctl get -bootstrap "$SEED_ADDR" -cap /handoff/secret.cap \
       -key "$WORK/attacker.key" -o "$OUT" 2>/dev/null; then
    echo "   FAIL: opened a capability that was not shared with us"
    fail=1
  else
    echo "   OK: denied — a cap wrapped for another user will not unwrap with our key"
  fi
else
  echo "   FAIL: /handoff/secret.cap missing (did the client stage run?)"
  fail=1
fi

# 3) Raw shards on disk. Even with full read access to every node's blob store,
#    the plaintext canary must not appear anywhere: the nodes hold ciphertext.
echo ">> attempt 3: hunt the plaintext canary in every node's raw shards"
if [ -f /handoff/marker.txt ]; then
  MARKER="$(cat /handoff/marker.txt)"
  leaked=""
  for m in "${NODE_MOUNTS[@]}"; do
    # -a: treat binary shards as text; -r recursive; -q quiet; -F literal.
    if grep -arqF "$MARKER" "$m/shards" 2>/dev/null; then
      leaked="$leaked $m"
    fi
  done
  if [ -n "$leaked" ]; then
    echo "   FAIL: plaintext canary found in raw shards on:$leaked"
    fail=1
  else
    echo "   OK: denied — no node's shards contain the plaintext (all ciphertext)"
  fi
else
  echo "   FAIL: /handoff/marker.txt missing (did the client stage run?)"
  fail=1
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "PASS: an unauthorized client was denied on every path (network, cap, raw shards)."
  exit 0
fi
echo "FAIL: an unauthorized client gained access it should not have."
exit 1
