#!/usr/bin/env bash
#
# Multi-device write reconciliation, run inside the compose `race` service.
#
# This is the end-to-end proof for Architecture §3.7.1: two devices belonging to
# ONE User share a single Ed25519 owner signing key (the only authority that can
# advance the namespace root) but each keep their own workspace — their own
# root.json, base.json, and device tag. Because a DHT has no compare-and-swap,
# two devices committing against the same base would, naively, clobber each
# other. revika instead runs a read-merge-publish loop on every commit:
#
#   * the public DHT root is key-stripped (verify projection), so a device cannot
#     decrypt another device's tree from it. Each commit therefore ALSO publishes
#     a "sealed self-root" companion under /revika-fullcap/<owner> — the full root
#     cap (with AES key) sealed to the owner's OWN ML-KEM key, so only the User's
#     own devices (which share keys/user.key) can open it;
#   * a committing device fetches the peer's verify-root + companion, three-way-
#     merges (manifest.Merge3) its local tip against the remote over a local merge
#     base (base.json), and publishes a root containing BOTH sides;
#   * disjoint edits merge silently; a path both devices edited differently keeps
#     one side under its name and files the other as a "(conflict <tag>)" copy —
#     never a silent lost update.
#
# The two "devices" here are two workspaces on the shared /revika DHT (seed +
# node2 + node3), sharing the owner identity via a copied keys/ dir. The commit
# merge is inline and sequential, so driving the two workspaces in turn from one
# script exercises the exact read-merge-publish path a real second device would.
# It asserts:
#
#   1. the client discovers every storage node over the DHT;
#   2. DISJOINT writes converge: device A writes a.txt, device B (which never saw
#      A) writes b.txt and its commit merges A's tree in; a later write on A folds
#      B's tree back, so BOTH devices' `ls` eventually agree on {a,b,c} with every
#      file byte-identical — no write lost;
#   3. a GENUINE collision (both devices write the same path with different bytes)
#      yields the kept file PLUS one "(conflict <tag>)" copy, and both versions
#      are recoverable byte-identically — divergence surfaces, never silent loss;
#   4. the earlier disjoint files survive the collision commit untouched.
#
# Exit status is 0 only if all hold, so a compose run surfaces a failure as a
# non-zero exit for this service. Run it with:
#   docker compose run --build --rm race
set -euo pipefail

: "${SEED_ADDR:?SEED_ADDR must point at the seed node /p2p multiaddr}"

WORK=/tmp/revika-race
WS_A="$WORK/deviceA"            # device A's workspace (config.json + root.json + base.json)
WS_B="$WORK/deviceB"            # device B's workspace
OUT="$WORK/out"                # scratch for retrievals
rm -rf "$WORK"
mkdir -p "$OUT"

# Distinct payloads so a lost/merged/conflicted write is unambiguous on retrieval.
BYTES_A="device-A-wrote-this-alpha"
BYTES_B="device-B-wrote-this-bravo"
BYTES_C="device-A-wrote-this-charlie"
COLLIDE_A="COLLISION-from-device-A-11111111"
COLLIDE_B="COLLISION-from-device-B-22222222"

# --- one shared owner identity, two devices ---------------------------------
# The User has ONE owner identity (ML-KEM receiving key + Ed25519 signing key).
# Both devices must sign as it (to advance the same root) AND hold its ML-KEM key
# (to open the sealed self-root companion). Mint it once, then copy it into each
# workspace's keys/ dir, replacing the throwaway identity `connect` minted.
echo ">> minting the shared owner identity (one User, two devices)"
revika-ctl keygen -key "$WORK/owner" -pow-difficulty 0 >/dev/null
SIGNKEY="$WORK/owner.sign.key"
OWNER_PUB="$WORK/owner.sign.pub"

echo ">> creating two workspaces bootstrapped through the seed"
revika-ctl connect -root "$WS_A" -bootstrap "$SEED_ADDR" >/dev/null
revika-ctl connect -root "$WS_B" -bootstrap "$SEED_ADDR" >/dev/null

# Overwrite each workspace's keys with the shared owner identity. The device tag
# (config.json) and root/base sidecars stay per-workspace, so the two devices
# diverge exactly as two machines would.
for ws in "$WS_A" "$WS_B"; do
  cp "$WORK/owner.key"      "$ws/keys/user.key"
  cp "$WORK/owner.pub"      "$ws/keys/user.pub"
  cp "$WORK/owner.sign.key" "$ws/keys/user.sign.key"
  cp "$WORK/owner.sign.pub" "$ws/keys/user.sign.pub"
done
echo "OK: both workspaces now share one owner identity (distinct device tags/roots)"

# Discover every storage node over the DHT (see verify.sh / tree.sh rationale).
EXPECTED_NODES=3
echo ">> discovering storage nodes via bootstrap $SEED_ADDR (expect $EXPECTED_NODES)"
reachable=0
for attempt in 1 2 3 4 5 6; do
  nodes_out=$(revika-ctl node -root "$WS_A" || true)
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

# put <workspace> <rvk-path> <local-file> — store a file into a device's namespace,
# retrying while DHT discovery settles. Each commit runs the read-merge-publish
# loop against whatever the OTHER device last published.
put() {
  local ws="$1" dst="$2" src="$3" ok=""
  for attempt in 1 2 3 4 5; do
    if revika-ctl cp -root "$ws" -signkey "$SIGNKEY" "$src" "$dst"; then
      ok=1
      break
    fi
    echo "   store $dst attempt $attempt failed; retrying in 5s..."
    sleep 5
  done
  [ -n "$ok" ] || { echo "FAIL: cp $src $dst never succeeded"; exit 1; }
}

# lsline <workspace> <rvk-path> — print one entry name per line for a directory.
lsline() { revika-ctl ls -root "$1" "$2"; }

# published_seq <workspace> — the owner's currently PUBLISHED root sequence as
# seen over the DHT (empty until the root propagates). `ls -owner` reads the
# signing pubkey from a FILE and returns a verify-only view; the trailing
# `|| true` keeps a not-yet-resolvable lookup from tripping `set -e`/`pipefail`.
published_seq() {
  revika-ctl ls -root "$1" -owner "$OWNER_PUB" 2>/dev/null \
    | sed -n 's/^[[:space:]]*seq:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n1 || true
}

# wait_advance <peer-workspace> <baseline-seq> — block until the peer resolves a
# published root strictly newer than baseline, i.e. the writer's last commit has
# propagated far enough for the peer's next commit to merge against it. The DHT is
# eventually consistent, so a real second device would likewise wait/retry; this
# turns that latency into a bounded poll instead of a race the assertions could lose.
wait_advance() {
  local ws="$1" baseline="$2" s
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    s=$(published_seq "$ws")
    if [ -n "$s" ] && [ "$s" -gt "$baseline" ]; then
      echo "   propagated: peer now sees published seq $s (> $baseline)"
      return 0
    fi
    echo "   peer sees published seq ${s:-<none>} (want > $baseline); waiting 5s..."
    sleep 5
  done
  echo "FAIL: the writer's commit never propagated past seq $baseline over the DHT"
  exit 1
}

# getbytes <workspace> <rvk-path> — retrieve a single file and echo its bytes.
getbytes() {
  local ws="$1" p="$2" dstdir out
  dstdir=$(mktemp -d "$OUT/get.XXXXXX")
  local ok=""
  for attempt in 1 2 3 4 5; do
    # cp's own progress goes to stderr so only the file bytes reach stdout, which
    # the caller captures via command substitution.
    if revika-ctl cp -root "$ws" "$p" "$dstdir/" >&2; then
      ok=1
      break
    fi
    echo "   retrieve $p attempt $attempt failed; retrying in 5s..." >&2
    sleep 5
  done
  [ -n "$ok" ] || { echo "FAIL: cp $p (retrieve) never succeeded" >&2; exit 1; }
  # cp rvk:dir/file dstdir/ writes dstdir/<basename>.
  out="$dstdir/$(basename "$p")"
  [ -f "$out" ] || { echo "FAIL: retrieval of $p produced no file at $out" >&2; exit 1; }
  cat "$out"
}

printf '%s' "$BYTES_A" >"$WORK/a.txt"
printf '%s' "$BYTES_B" >"$WORK/b.txt"
printf '%s' "$BYTES_C" >"$WORK/c.txt"
printf '%s' "$COLLIDE_A" >"$WORK/collideA.txt"
printf '%s' "$COLLIDE_B" >"$WORK/collideB.txt"

# --- phase 1: disjoint writes converge without loss --------------------------
echo
base=$(published_seq "$WS_A"); base=${base:-0}
echo ">> [phase 1] device A writes rvk:shared/a.txt"
put "$WS_A" rvk:shared/a.txt "$WORK/a.txt"

echo ">> [phase 1] waiting for A's root to reach device B before B commits"
wait_advance "$WS_B" "$base"

echo ">> [phase 1] device B writes rvk:shared/b.txt — its commit must merge A in"
before_b=$(published_seq "$WS_B"); before_b=${before_b:-0}
put "$WS_B" rvk:shared/b.txt "$WORK/b.txt"

echo ">> [phase 1] device B's view of rvk:shared (must already show BOTH a.txt and b.txt):"
b_list=$(lsline "$WS_B" rvk:shared)
printf '%s\n' "$b_list" | sed 's/^/     /'
if ! printf '%s\n' "$b_list" | grep -qx 'a.txt' || ! printf '%s\n' "$b_list" | grep -qx 'b.txt'; then
  echo "FAIL: device B's merge did not contain both a.txt and b.txt"
  exit 1
fi
echo "OK: device B's commit merged device A's a.txt in alongside its own b.txt"

echo ">> [phase 1] waiting for B's merged root to reach device A before A commits"
wait_advance "$WS_A" "$before_b"

echo ">> [phase 1] device A writes rvk:shared/c.txt — this commit must fold B's b.txt back into A"
put "$WS_A" rvk:shared/c.txt "$WORK/c.txt"

echo ">> [phase 1] device A's view of rvk:shared (must now show a.txt, b.txt AND c.txt — converged):"
a_list=$(lsline "$WS_A" rvk:shared)
printf '%s\n' "$a_list" | sed 's/^/     /'
for f in a.txt b.txt c.txt; do
  if ! printf '%s\n' "$a_list" | grep -qx "$f"; then
    echo "FAIL: device A's converged view is missing $f (a write was lost)"
    exit 1
  fi
done
echo "OK: both devices converged on {a.txt, b.txt, c.txt} — no disjoint write was lost"

echo ">> [phase 1] every converged file must be byte-identical to what was written"
[ "$(getbytes "$WS_A" rvk:shared/a.txt)" = "$BYTES_A" ] || { echo "FAIL: a.txt bytes wrong"; exit 1; }
[ "$(getbytes "$WS_A" rvk:shared/b.txt)" = "$BYTES_B" ] || { echo "FAIL: b.txt bytes wrong"; exit 1; }
[ "$(getbytes "$WS_A" rvk:shared/c.txt)" = "$BYTES_C" ] || { echo "FAIL: c.txt bytes wrong"; exit 1; }
echo "OK: a.txt, b.txt, c.txt all reconstructed byte-identically after the merges"

# --- phase 2: a genuine collision yields a conflict copy, never a lost write --
echo
before_b2=$(published_seq "$WS_B"); before_b2=${before_b2:-0}
echo ">> [phase 2] device B writes rvk:shared/same.txt = '$COLLIDE_B'"
put "$WS_B" rvk:shared/same.txt "$WORK/collideB.txt"

echo ">> [phase 2] waiting for B's same.txt to reach device A before A's colliding write"
wait_advance "$WS_A" "$before_b2"

echo ">> [phase 2] device A writes rvk:shared/same.txt = '$COLLIDE_A' — same path, different bytes => CONFLICT"
put "$WS_A" rvk:shared/same.txt "$WORK/collideA.txt"

echo ">> [phase 2] device A's view of rvk:shared (must show same.txt AND a '(conflict <tag>)' copy):"
final=$(lsline "$WS_A" rvk:shared)
printf '%s\n' "$final" | sed 's/^/     /'
if ! printf '%s\n' "$final" | grep -qx 'same.txt'; then
  echo "FAIL: same.txt vanished after the collision merge"
  exit 1
fi
conflict_name=$(printf '%s\n' "$final" | grep -F 'conflict' | head -n1 || true)
if [ -z "$conflict_name" ]; then
  echo "FAIL: the collision produced no conflict copy (a write may have been silently lost)"
  exit 1
fi
echo "OK: collision produced same.txt plus a conflict copy: '$conflict_name'"

echo ">> [phase 2] both colliding versions must be recoverable (nothing silently dropped)"
kept=$(getbytes "$WS_A" rvk:shared/same.txt)
other=$(getbytes "$WS_A" "rvk:shared/$conflict_name")
if [ "$kept" = "$other" ]; then
  echo "FAIL: the conflict copy is identical to the kept file — a side was lost"
  exit 1
fi
got_a=""; got_b=""
for v in "$kept" "$other"; do
  [ "$v" = "$COLLIDE_A" ] && got_a=1
  [ "$v" = "$COLLIDE_B" ] && got_b=1
done
if [ -z "$got_a" ] || [ -z "$got_b" ]; then
  echo "FAIL: the two surviving copies are not {A's bytes, B's bytes} (got '$kept' and '$other')"
  exit 1
fi
echo "OK: both device-A and device-B versions of same.txt survived (kept + conflict copy)"

echo ">> [phase 2] the phase-1 files must still be intact after the collision commit"
[ "$(getbytes "$WS_A" rvk:shared/a.txt)" = "$BYTES_A" ] || { echo "FAIL: a.txt lost across the collision"; exit 1; }
[ "$(getbytes "$WS_A" rvk:shared/b.txt)" = "$BYTES_B" ] || { echo "FAIL: b.txt lost across the collision"; exit 1; }
[ "$(getbytes "$WS_A" rvk:shared/c.txt)" = "$BYTES_C" ] || { echo "FAIL: c.txt lost across the collision"; exit 1; }
echo "OK: a.txt, b.txt, c.txt survived the collision commit untouched"

echo
echo "PASS: two devices sharing one owner key committed divergent roots over the"
echo "      DHT; disjoint writes converged with no lost update, and a genuine"
echo "      same-path collision produced a conflict copy keeping BOTH versions —"
echo "      reconciled inline on the commit path, no daemon, no bearer token."
