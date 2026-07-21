#!/usr/bin/env bash
#
# Store/retrieve helper for the node-down resilience scenario (deploy/resilience.sh).
#
# The scenario proves the erasure-coding durability guarantee end to end: a file
# becomes k=4 data + m=2 parity = 6 shards spread round-robin across the 3 nodes
# (2 per node), so losing one whole node loses 2 shards, and any k=4 of the 6
# still reconstruct the file.
#
# It is deliberately split into two one-shot invocations, `store` and `get`, so
# the orchestrator can stop a node *in between*:
#   * store — writes a random file and its manifest to the shared /handoff volume,
#   * get   — reads that manifest back (with a node down) and asserts the file is
#             recovered byte-identically.
set -euo pipefail

: "${SEED_ADDR:?SEED_ADDR must point at the seed node /p2p multiaddr}"

SRC=/handoff/resilience-src.bin
MANIFEST=/handoff/resilience.rvk.json

# DHT discovery + provider records are eventually consistent, so allow a few
# attempts before giving up.
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

case "${1:-}" in
  store)
    echo ">> [store] generating a 1 MiB file and storing it across all nodes"
    head -c 1048576 /dev/urandom >"$SRC"
    retry "put" revika-ctl put -bootstrap "$SEED_ADDR" -manifest "$MANIFEST" "$SRC" \
      || { echo "FAIL: put never succeeded"; exit 1; }
    [ -s "$MANIFEST" ] || { echo "FAIL: no manifest written"; exit 1; }
    echo "OK: stored; source + manifest saved under /handoff"
    ;;

  get)
    echo ">> [get] retrieving with a node DOWN (any k=4 of 6 shards suffice)"
    [ -s "$MANIFEST" ] || { echo "FAIL: /handoff manifest missing (did 'store' run?)"; exit 1; }
    OUT=/tmp/resilience-out.bin
    retry "get" revika-ctl get -bootstrap "$SEED_ADDR" -manifest "$MANIFEST" -o "$OUT" \
      || { echo "FAIL: get never succeeded (could not gather k shards from the survivors)"; exit 1; }
    if cmp -s "$SRC" "$OUT"; then
      echo
      echo "PASS: file retrieved byte-identical despite a node being down."
    else
      echo "FAIL: retrieved file differs from the original"
      exit 1
    fi
    ;;

  *)
    echo "usage: resilience-client.sh {store|get}" >&2
    exit 2
    ;;
esac
