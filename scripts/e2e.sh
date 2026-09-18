#!/usr/bin/env bash
# End-to-end smoke of the revika IPFS adapter stack as three separate processes:
#
#   revika-kubo-stub  <--MFS HTTP RPC--  revika-ipfs-adapter  <--rvk-plugin-v1 frames--  revika-smoke
#         (stub Kubo)                          (Hop B / Hop A)                              (client)
#
# It builds the real cmd/ binaries (cgo-free), wires them over loopback with a stub Kubo so
# nothing touches the public IPFS network, runs the smoke client's full Put/Get/Has/Delete
# round-trip, and fails if any process exits non-zero. This is the hermetic, Docker-free E2E
# job; deploy/ipfs runs the same client against a real (offline) Kubo for fidelity.
set -euo pipefail

# Loopback-only ports; uncommon values to avoid colliding with anything else on the runner.
KUBO_STUB_ADDR="${KUBO_STUB_ADDR:-127.0.0.1:5599}"
ADAPTER_ADDR="${ADAPTER_ADDR:-127.0.0.1:9599}"
export REVIKA_ADAPTER_SECRET="${REVIKA_ADAPTER_SECRET:-e2e-shared-secret-$(date +%s)}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="$(mktemp -d)"
pids=()

cleanup() {
  local status=$?
  for pid in "${pids[@]:-}"; do
    [[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null || true
  done
  rm -rf "${bin_dir}"
  exit "${status}"
}
trap cleanup EXIT INT TERM

log() { printf '=== %s\n' "$*"; }

# Wait until something is listening on host:port, or fail after ~15s.
wait_for_port() {
  local host="${1%%:*}" port="${1##*:}"
  for _ in $(seq 1 150); do
    if (exec 3<>"/dev/tcp/${host}/${port}") 2>/dev/null; then
      exec 3>&- 3<&-
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for ${1}" >&2
  return 1
}

log "building binaries (CGO_ENABLED=0)"
export CGO_ENABLED=0
go build -o "${bin_dir}/revika-kubo-stub" "${repo_root}/cmd/revika-kubo-stub"
go build -o "${bin_dir}/revika-ipfs-adapter" "${repo_root}/cmd/revika-ipfs-adapter"
go build -o "${bin_dir}/revika-smoke" "${repo_root}/cmd/revika-smoke"

log "starting stub Kubo on ${KUBO_STUB_ADDR}"
REVIKA_KUBO_STUB_LISTEN="${KUBO_STUB_ADDR}" "${bin_dir}/revika-kubo-stub" &
pids+=("$!")
wait_for_port "${KUBO_STUB_ADDR}"

log "starting adapter on ${ADAPTER_ADDR}"
REVIKA_ADAPTER_LISTEN="${ADAPTER_ADDR}" \
  REVIKA_IPFS_API="http://${KUBO_STUB_ADDR}" \
  "${bin_dir}/revika-ipfs-adapter" &
pids+=("$!")
wait_for_port "${ADAPTER_ADDR}"

log "running smoke client against ${ADAPTER_ADDR}"
REVIKA_ADAPTER_ADDR="${ADAPTER_ADDR}" "${bin_dir}/revika-smoke"

log "E2E PASS"
