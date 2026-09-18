# revika IPFS adapter stack

A runnable reference deployment of a revika **out-of-process storage adapter** (see
`docs/Architecture.md` §4.5.1). It wires four services together:

```
revika-smoke (client)    ──rvk-plugin-v1 over TCP──▶ revika-ipfs-adapter ──HTTP MFS RPC──▶ kubo
revika-client-smoke (client-ns) ──rvk-plugin-v1──▶            Hop B: the adapter's own concern
        Hop A: the normative revika adapter contract
```

- **kubo** — an IPFS node (`ipfs/kubo`). The real storage backend.
- **adapter** (`revika-ipfs-adapter`) — a `store.Store` server. It authenticates each peer with
  a shared-secret HMAC handshake, then answers Put/Get/Has/Delete over the size-prefixed
  `rvk-plugin-v1` frame protocol, mapping each object to an MFS path
  (`/revika/<sha256(id)>`) via Kubo's `/api/v0/files/*` RPC. It never sees plaintext or keys —
  only opaque ciphertext and hashed identifiers cross the boundary.
- **client** (`revika-smoke`) — a demo that dials the adapter and runs a full store-level
  round-trip: Put → Get (byte-for-byte check) → Has → Delete → Has (must report absence). It
  exits 0 on success, non-zero on any mismatch.
- **client-ns** (`revika-client-smoke`) — drives the real `revika-client` CLI end-to-end over
  the `rvk:`-prefixed namespace: `cp` (upload) → `ls` → `cp` (download, byte-for-byte check) →
  `rm` → `ls` (must no longer list the item). It exits 0 on success, non-zero on any mismatch.

## Run it

```sh
cd deploy/ipfs
export REVIKA_ADAPTER_SECRET=$(openssl rand -hex 32)
docker compose up --build
```

Compose builds all revika binaries into one cgo-free image, starts Kubo, waits for it to
become healthy, starts the adapter, then runs both smoke clients once. Watch the result:

```sh
docker compose logs client client-ns
```

A passing run ends with:

```
revika-smoke: connected to adapter at adapter:9090
revika-smoke: put 36 bytes as "smoke-test-object"
revika-smoke: get returned 36 bytes, matches
revika-smoke: has reports present
revika-smoke: deleted object
revika-smoke: has reports absent after delete
revika-smoke: PASS
```

```
revika-client-smoke: adapter at adapter:9090 is accepting connections
revika-client-smoke: pwd reports rvk:/
revika-client-smoke: uploaded smoke.txt
revika-client-smoke: ls lists smoke.txt
revika-client-smoke: downloaded content matches byte-for-byte
revika-client-smoke: removed smoke.txt
revika-client-smoke: ls no longer lists smoke.txt after rm
revika-client-smoke: PASS
```

Tear down (and drop the Kubo data volume):

```sh
docker compose down -v
```

## Configuration

| Service | Variable | Meaning | Default |
| --- | --- | --- | --- |
| adapter | `REVIKA_ADAPTER_LISTEN` | TCP listen address | `:9090` |
| adapter | `REVIKA_IPFS_API` | Kubo RPC base URL | `http://kubo:5001` |
| adapter, client, client-ns | `REVIKA_ADAPTER_SECRET` | Shared handshake secret (**required**) | — |
| client, client-ns | `REVIKA_ADAPTER_ADDR` | Adapter address to dial | `adapter:9090` |
| client-ns | `REVIKA_CLIENT_BIN` | Path to the `revika-client` binary it drives | `/usr/local/bin/revika-client` |

## Notes and limits

- The handshake authenticates peers against impersonation; it does **not** encrypt the
  envelope. Payloads are already end-to-end encrypted by the Client; on an untrusted segment,
  front the bridge with TLS (out of scope here — deferred per §4.5.1).
- The adapter is stateless: object identity is a hash of the opaque `ObjectID`, so any adapter
  replica against the same Kubo node serves the same objects.
- CI exercises this stack two ways (`.github/workflows/e2e.yml`): an `e2e-docker` job runs
  this compose with the `docker-compose.ci.yml` overlay, which forces Kubo fully **offline**
  (no DHT/bootstrap/public dials) so the real Kubo MFS API is tested without any egress, and
  checks the exit code of both `client` and `client-ns`; and a faster, Docker-free `e2e-stub`
  job (`scripts/e2e.sh`) runs the store-level adapter and smoke-client binaries against the
  pure-Go `revika-kubo-stub` instead of a real Kubo node. The protocol, adapter, and store
  logic are also covered by unit tests
  (`go test ./internal/netframe/... ./internal/ipfsstore/...`).

### CI overlay

To reproduce the `e2e-docker` job locally:

```sh
cd deploy/ipfs
export REVIKA_ADAPTER_SECRET=$(openssl rand -hex 32)
docker compose -f docker-compose.yml -f docker-compose.ci.yml up --build --abort-on-container-exit
docker compose -f docker-compose.yml -f docker-compose.ci.yml ps -a
```

A passing run shows both `client` and `client-ns` containers exited with code `0`.
