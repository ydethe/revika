#!/usr/bin/env sh
# Generate an EPHEMERAL, git-ignored, dev-only libp2p seed identity for the local
# docker-compose network and print the SEED_ADDR the other nodes bootstrap through.
#
# The repository no longer ships a committed seed key (issue #13): a well-known
# private key checked into source is a credential leak. Instead, mint a fresh one
# locally before bringing the network up. The key lands at deploy/seed.key, which
# is git-ignored (*.key), and docker-compose bind-mounts it read-only into the seed.
#
# Usage:
#   export SEED_ADDR="$(./deploy/gen-seed-key.sh)"   # generate + capture the addr
#   docker compose up --build
#
# In CI:
#   echo "SEED_ADDR=$(./deploy/gen-seed-key.sh)" >> "$GITHUB_ENV"
#
# It refuses to overwrite an existing deploy/seed.key; remove it first to rotate.
# Only the SEED_ADDR multiaddr is written to stdout (safe to capture in $(...));
# diagnostics go to stderr.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEY_PATH="${1:-$ROOT/deploy/seed.key}"

# The seed listens on tcp/4001 and is reachable on the compose network as the
# service DNS name "seed". Peers dial /dns4/seed/tcp/4001/p2p/<peer-id>.
SEED_HOST="${SEED_HOST:-seed}"
SEED_PORT="${SEED_PORT:-4001}"

# Mint the key via revika-ctl (stdout = Peer ID only). Build once via `go run`.
peerid="$(cd "$ROOT" && go run ./cmd/revika-ctl nodekey -o "$KEY_PATH")"

printf '/dns4/%s/tcp/%s/p2p/%s\n' "$SEED_HOST" "$SEED_PORT" "$peerid"
