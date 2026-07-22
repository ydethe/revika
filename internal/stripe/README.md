# stripe

Non-confidential erasure metadata (`Descriptor`) plus a User-signed repair
capability (`Grant`) that together let a dumb, untrusted Node take part in repair
without ever seeing plaintext or holding the User's keys.

## Purpose

A shard by itself tells a Node nothing about its erasure context — which other
shards belong to the same Reed–Solomon stripe, or how many are needed to
reconstruct. This package carries exactly that context and *nothing else*. It
deliberately omits the per-chunk encryption key (which lives only in the User's
manifest), so distributing this metadata to nodes leaks no plaintext: shards are
already ciphertext addressed by hash, and repair runs purely on ciphertext
(`erasure.Encode` is deterministic, so regenerated shards reproduce their exact
content addresses).

## Descriptor

`Descriptor` is the erasure context of one stripe:

- `K`, `M` — Reed–Solomon data and parity counts.
- `Shards []store.ShardID` — ordered content addresses of the N = K+M shards.
  Order is significant: index maps directly to erasure position (first `K` are
  data, the rest parity) and must be preserved on the wire and in storage.

Methods:

- `N() int` — total shard count (`K + M`).
- `Contains(id store.ShardID) bool` — whether `id` is one of the stripe's shards.
- `MarshalBinary() ([]byte, error)` — canonical fixed layout
  `uint16 K | uint16 M | uint16 N | N * 32-byte shard IDs` in position order
  (never sorted); validates params. `UnmarshalDescriptor([]byte)` parses it back,
  rejecting truncated/malformed blobs by checking `N == K+M` and byte length.

## Grant (signed repair capability)

When a repairing node regenerates a missing shard and stores it on a fresh node,
that node's ledger demands proof of ownership — but the repairing node does not
hold the User's signing key. A `Grant` is a User-signed token, distributed with
the Descriptor, authorizing storage of *any shard whose content address is in this
stripe*, attributed to the signing User. Content addressing bounds it tightly: the
bearer can only store the exact bytes hashing to a listed ID, and cannot grow the
stripe beyond its N shards.

Wire layout is fixed (`GrantSize`): `owner(32) || expiry(8, BE unix seconds) ||
sig(64)`. The signed payload is `grantDomain || expiry(8) || MarshalBinary(desc)`,
where `grantDomain` (`"revika/repair-grant/1"`) provides versioned domain
separation so a Grant signature is never confused with another Ed25519 signature.
Signing over the full descriptor binds the Grant to this precise stripe, so it
cannot be lifted onto a different one.

Functions:

- `BuildGrant(signer cap.SignKey, d Descriptor, expiry int64) ([]byte, error)` —
  signs a grant; `expiry` is a unix timestamp, or `0` for a grant that never
  expires (current default — repair must work with no User online).
- `VerifyGrant(grant []byte, d Descriptor, now time.Time) (owner []byte, err error)` —
  validates the grant against `d` at wall-clock `now` and returns the owner's
  public-key bytes (the ledger owner identity). Fails on malformed input, wrong
  key, descriptor mismatch, or a non-zero expiry in the past.

## Putter

`Putter` is an optional capability a `store.Store` may implement:
`PutStripe(ctx, data, d) (store.ShardID, error)` stores a shard together with its
Descriptor so the receiving Node can record the erasure context and take part in
repair. The pipeline type-asserts for it and falls back to a plain `Put` for
stores (e.g. mock/in-memory) that do not participate in networked repair.

## Fit within revika

This package is the bridge that makes ciphertext-only repair possible: nodes learn
*how* shards relate (Descriptor) and are *authorized* to store regenerated shards
(Grant) without ever gaining access to decryption keys. It upholds the guiding
principle that nodes are dumb, untrusted blob stores trusted for availability,
never confidentiality.
