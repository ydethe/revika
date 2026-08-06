#!/usr/bin/env bash
#
# End-to-end multi-node check, run inside the compose `client` service.
#
# It joins the revika DHT through the seed node (SEED_ADDR), stores a random
# test file so the pipeline spreads its erasure-coded shards across the
# discovered storage nodes, then asserts four things:
#
#   1. the client discovers EVERY storage node over the DHT — not just the
#      bootstrap seed. The client bootstraps through the seed only; it then finds
#      the rest via the DHT rendezvous (revika/storage) that each node advertises,
#      so mDNS is off and no node is named explicitly. This asserts that channel
#      actually reaches the whole network,
#   2. cp (store) succeeds and advances the signed root pointer (root.json),
#   3. EVERY node's on-disk shard store gained shards (the node data volumes are
#      bind-mounted read-only under /nodes/<name>, so we can count them),
#   4. cp (retrieve) reconstructs a file byte-identical to the original.
#
# Exit status is 0 only if all four hold, so `docker compose up` surfaces a
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
WS="$WORK/ws"                    # the User's workspace (config.json + root.json + keys)
ROOTFILE="$WS/root.json"         # the User's signed namespace anchor

# A distinctive plaintext canary we embed at the start of the payload. The
# unauthorized-access client (deploy/attack.sh) later hunts for it in the raw
# shards on the nodes: it must NOT appear there, proving nodes hold only
# ciphertext. Long and unique enough that a chance hit in random data is nil.
MARKER="REVIKA-PLAINTEXT-CANARY-DO-NOT-LEAK-cf83e1357eefb8bd"

# ~1 MiB payload: canary line + random bytes => one 4 MiB-max chunk => k=4 data +
# m=2 parity = 6 shards, which round-robin across 3 nodes as 2 shards each.
echo ">> generating ~1 MiB test file with a plaintext canary"
printf '%s\n' "$MARKER" >"$SRC"
head -c 1048576 /dev/urandom >>"$SRC"

# Storing is an authenticated write: the client signs each PUT with its Ed25519
# signing key (its storage owner identity), so generate one and pass it to cp via
# -signkey. This is also the key that authorizes a later rm.
echo ">> generating the client's signing identity"
revika-ctl keygen -key "$WORK/user" -pow-difficulty 0 >/dev/null
SIGNKEY="$WORK/user.sign.key"

# Create a workspace whose saved config.json carries the bootstrap peer, so every
# namespace command reaches the network via -root (bootstrap is no longer a
# per-command flag). The seed is the sole bootstrap; the rest are found via the DHT.
echo ">> creating a workspace bootstrapped through the seed"
revika-ctl connect -root "$WS" -bootstrap "$SEED_ADDR" >/dev/null

count_shards() { find "$1/shards" -type f 2>/dev/null | wc -l | tr -d ' '; }

# The client bootstraps ONLY through the seed (SEED_ADDR), yet it must discover
# every storage node over the DHT — each node advertises itself under the
# revika/storage rendezvous, so the client finds the rest without mDNS and
# without naming any node. Assert that the client sees ALL nodes and can reach
# them, not just the seed: if discovery regressed to seed-only, shards would
# silently colocate and the failure-domain guarantee would be lost. DHT discovery
# is eventually consistent (advertise records + routing tables converge
# asynchronously), so poll a few times before failing.
EXPECTED_NODES=${#NODE_MOUNTS[@]}   # seed + node2 + node3
echo ">> discovering storage nodes via bootstrap $SEED_ADDR (expect all $EXPECTED_NODES)"
reachable=0
for attempt in 1 2 3 4 5 6; do
  nodes_out=$(revika-ctl node -root "$WS" || true)
  printf '%s\n' "$nodes_out" | sed 's/^/     /'
  # Parse "Discovered N storage node(s) via the DHT (M reachable):"
  discovered=$(printf '%s\n' "$nodes_out" | sed -n 's/^Discovered \([0-9]*\) storage node.*/\1/p')
  reachable=$(printf '%s\n' "$nodes_out" | sed -n 's/.*(\([0-9]*\) reachable).*/\1/p')
  discovered=${discovered:-0}
  reachable=${reachable:-0}
  if [ "$reachable" -ge "$EXPECTED_NODES" ]; then
    break
  fi
  echo "   discovered $discovered node(s), $reachable reachable of $EXPECTED_NODES; retrying in 5s..."
  sleep 5
done
if [ "$reachable" -lt "$EXPECTED_NODES" ]; then
  echo "FAIL: client reached only $reachable of $EXPECTED_NODES storage nodes over the DHT"
  echo "      (it must discover the whole network via the rendezvous, not just the bootstrap seed)"
  exit 1
fi
echo "OK: client discovered and reached all $EXPECTED_NODES storage nodes via the DHT (bootstrap was seed-only)"

echo ">> shard counts BEFORE store:"
declare -A before
for m in "${NODE_MOUNTS[@]}"; do
  before[$m]=$(count_shards "$m")
  echo "     $m: ${before[$m]}"
done

# DHT discovery is eventually consistent (advertise records + routing tables
# converge asynchronously), so give the store a few attempts before failing.
echo ">> cp \$SRC rvk:testfile.bin via bootstrap $SEED_ADDR"
put_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl cp -root "$WS" -signkey "$SIGNKEY" "$SRC" rvk:testfile.bin; then
    put_ok=1
    break
  fi
  echo "   store attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$put_ok" ] || { echo "FAIL: cp (store) never succeeded"; exit 1; }
[ -s "$ROOTFILE" ] || { echo "FAIL: no root pointer written"; exit 1; }

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

echo ">> cp rvk:testfile.bin \$OUT via bootstrap $SEED_ADDR"
get_ok=""
for attempt in 1 2 3 4 5; do
  if revika-ctl cp -root "$WS" rvk:testfile.bin "$OUT"; then
    get_ok=1
    break
  fi
  echo "   retrieve attempt $attempt failed; retrying in 5s..."
  sleep 5
done
[ -n "$get_ok" ] || { echo "FAIL: cp (retrieve) never succeeded"; exit 1; }

if cmp -s "$SRC" "$OUT"; then
  echo "OK: retrieved file is byte-identical to the original"
else
  echo "FAIL: retrieved file differs from the original"
  exit 1
fi

# --- hand off artifacts for the unauthorized-access client (deploy/attack.sh) --
# A separate `attacker` client will try, and must fail, to read this data. We
# give it only what a real adversary could plausibly obtain — never our own root
# pointer (the read-capability) nor any private key:
#   * secret.root.json — a shared root SEALED for a THIRD party (not the attacker),
#                        as if the attacker intercepted a share meant for someone
#                        else; only that third party's key can open it;
#   * marker.txt       — the plaintext canary, so it knows what to hunt for.
# /handoff is a shared volume, present only under compose (skipped when this
# script is run standalone).
if [ -d /handoff ]; then
  echo ">> preparing handoff for the unauthorized-access client"
  revika-ctl keygen -key "$WORK/thirdparty" -pow-difficulty 0 >/dev/null
  revika-ctl share -root "$WS" -signkey "$SIGNKEY" \
    -to "@$WORK/thirdparty.pub" -o /handoff/secret.root.json rvk:testfile.bin >/dev/null
  printf '%s' "$MARKER" >/handoff/marker.txt
  echo "   wrote /handoff/secret.root.json (sealed for a third party) and /handoff/marker.txt"
fi

echo
echo "PASS: data was spread across all nodes and retrieved intact."
