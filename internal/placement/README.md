# placement

**Which nodes a User's shards land on.** A small, pure-Go policy layer the write
path consults before dispersing an erasure stripe, so no single failure domain
can hold enough of a stripe to matter
([Architecture §5](../../Architecture.md); the "richer policy planned" note in
[CLAUDE.md](../../CLAUDE.md)).

It is deliberately **framework-neutral** — it knows nothing about libp2p, the
DHT, or a `store.Store`. A `NodeID` is an opaque string
([`internal/net`](../net/README.md) maps a `peer.ID` to one via `peer.ID.String`),
and a `Node` is that ID plus the signals a policy weighs. This keeps the policy
unit-testable in isolation and lets the same decisions run over a mock or a real
network unchanged.

## Why placement matters

Erasure coding gives redundancy only if a stripe's `k+m` shards sit in
**independent failure domains**. Coding a file `k=4, m=2` and then storing all
six shards on one node (or six nodes on one subnet that share a switch, a power
feed, or an operator) buys nothing: lose that domain and you lose more than `m`
shards, so the file is unrecoverable. Placement is the component that spreads the
stripe so any `k` of the `k+m` survive the loss of a domain.

## The `Node` candidate

```go
type Node struct {
    ID     NodeID // opaque node identity (net derives it from a libp2p peer.ID)
    Domain string // failure domain (subnet/rack/operator); "" ⇒ the node is its own domain
    Free   int64  // advertised free bytes; 0 = unknown
    Weight int    // relative capacity/preference weight; <= 0 ⇒ 1
    Down   bool    // known-unavailable; excluded from selection
}
```

The **zero `Node` is usable** (`Down` defaults to false), so a caller with no
health or capacity data can pass bare `Node{ID: ...}` values and have them all
count.

## Two shapes of decision

| API | Granularity | Guarantee | Used by |
|---|---|---|---|
| **`Selector.Pick`** | one node per call (stateful) | distinct *consecutive* nodes | `net.PlacementStore` (per-shard `Put`) |
| **`Spread`** | a whole stripe per call | distinct *failure domains* across the stripe | a stripe-aware writer (planned) |

### `Selector` — per-shard

```go
type Selector interface {
    Pick(candidates []Node) (NodeID, error) // ErrNoCandidates if none usable
}
```

The pipeline stores a stripe's shards with **consecutive** `Put`s, so a
round-robin `Selector` lands them on consecutive distinct nodes — the diversity
the erasure margin depends on — without ever seeing the stripe as a whole.

- **`RoundRobin`** *(default)* — hands out usable candidates in turn. Advances by
  usable-position, so a `Down` node in the middle wastes no turn.
- **`Weighted`** — capacity-aware, using *smooth* weighted round-robin (the nginx
  SWRR algorithm) rather than randomness, so placement stays deterministic and
  the interleaving is even (weights `5,1,1` → `a,b,a,c,a,a,a`, never
  `a,a,a,a,a,b,c`). Feed it capacity with `WeightByFree`.

### `Spread` — whole-stripe

```go
func Spread(n int, candidates []Node) ([]NodeID, error)
```

Assigns all `n` shards of one stripe at once, so it can guarantee distinct
**failure domains**, not just distinct consecutive nodes. Preference order:

1. a node in a domain not yet used by this stripe;
2. a not-yet-used node in an already-used domain;
3. a repeat of an already-used node (only when `n` exceeds the usable node count).

Within a domain, roomier nodes (higher `Free`) come first, and the result is
**deterministic** for a given candidate set (ties broken by `NodeID`).

## `OffloadBytes` — the rebalancing decision

Placement above picks where a *new* shard lands. `OffloadBytes` is the pure
decision behind **rebalancing** the *standing* distribution (Architecture §3.4):
given this node's and a peer's `Load` (bytes `Used` out of a `Capacity` budget),
it returns how many bytes this node should push to the peer this round.

```go
type Load struct { Used, Capacity int64 } // Frac() = Used/Capacity clamped to [0,1]; Free() = remaining

func OffloadBytes(self, peer Load, threshold float64) int64
```

It balances the **fraction** full (`Load.Frac`), never raw counts, so a
Raspberry Pi and a cloud server converge on the same fullness rather than the
same shard count. It returns 0 unless `self` is fuller than `peer` by more than
`threshold` — the dead-band (hysteresis) that stops two near-equal nodes
ping-ponging a shard — and otherwise aims to close *half* the gap, capped by what
the peer can accept (`peer.Free`) and what this node holds. This is the
pairwise dimension-exchange step that, applied across a connected graph, drives
every node toward the global mean load. [`internal/net`](../net/README.md)'s
`Rebalancer` drives it: it queries peer load over `/revika/balance`, calls
`OffloadBytes`, and moves the node's coldest shards make-before-break.

## How it fits into revika

[`internal/net`](../net/README.md)'s `PlacementStore` (the write-side
`store.Store`) delegates its node choice to a `placement.Selector`, defaulting to
`RoundRobin` — the round-robin "first cut" now lives here rather than being baked
into `net`. `SetSelector` swaps in a capacity- or domain-aware policy. When the
write path is reworked to hand placement a whole stripe (its
[`stripe.Descriptor`](../stripe/) `K+M`) instead of one shard at a time, `Spread`
is the drop-in that upgrades the guarantee from "distinct consecutive nodes" to
"distinct failure domains".

Node **liveness, capacity, and reputation feeds** — the sources that populate
`Free`, `Down`, and `Weight` — are deferred (Architecture §5, alongside the
anti-Sybil/economic layers); until then callers pass what they know and the
policy degrades gracefully to round-robin over the reachable set.

## Testing

`go test ./internal/placement` (add `-race` for the concurrency guard). Tests
cover round-robin distinctness, SWRR proportionality and smoothness,
capacity weighting, domain spreading, over-subscription balance, determinism,
and concurrent `Pick` safety.
