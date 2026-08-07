# device

The **read-revocable device model** (Architecture §3.7.2): a User's *devices* as
individually-keyed, revocable members of the one User principal.

## Why it exists

Without it, every device of one User is cryptographically identical — all share the
one Ed25519 owner signing key and the one ML-KEM-768 keypair (§3.7.1). That makes
devices interchangeable but **unrevocable**: retiring a lost or compromised device
would mean rotating the owner identity, which changes the namespace address (the
owner pubkey) and breaks every published share and `ls -owner` resolution.

This package makes an individual device a first-class member with its **own** ML-KEM
keypair, authorized by an offline **master credential** (the owner Ed25519 key). A
device is never a third trust role — it sits entirely on the User side of the
User↔Node boundary — so this is a refinement of the **User** role.

The package is **pure and offline**: it never touches the network. The CLI
(`revika-ctl device`) drives it, persists the record at `<workspace>/devices.json`,
and mirrors it to the DHT best-effort (`net.DeviceAuthNamespace`).

## The record

- **`ID` / `NewID(pub)`** — a device's stable handle: `SHA-256(ML-KEM pubkey)`. It is
  *derived*, not chosen, so two records built from the same key agree on it and a
  device cannot claim an ID it has no key for. `String()`/`Short()` render it (full
  hex / git-style 8-byte prefix).
- **`Member{ID, Pub, Label, Added}`** — one authorized device: its derived ID, its
  ML-KEM public key (the seal recipient), an optional label, and the `Seq` it was
  enrolled at.
- **`Auth{Owner, Seq, Members, Sig}`** — the **device-authorization record** (DAR):
  the owner-signed, monotonic set of authorized devices. `Members` is kept sorted by
  ID so the signed payload is canonical regardless of insertion order.

## Operations

- **`Sign(signer)` / `Verify()`** — the master (owner) Ed25519 key is the sole
  authority that signs the set. `Sign` fills `Owner` + `Sig` over a domain-separated,
  length-prefixed payload (`revika/deviceauth/1.0.0`); `Verify` re-derives each
  member's ID from its pubkey and checks the signature, so a tampered member or
  spoofed ID is rejected.
- **`With(pub, label)` / `Without(id)`** — enroll / revoke, each returning an unsigned
  copy at `Seq+1` (monotonic, so a stale record can never win over the current one).
  Re-adding an authorized device or removing an absent one is an error, so a typo
  never mints a silent no-op.
- **`Authorized(id)` / `PubOf(id)` / `Recipients()`** — membership tests and the seal-
  recipient set (every member's ML-KEM pubkey) that `manifest.SealFullRootFor` seals
  the self-root companion to.
- **`Resolve(handle)`** — maps a full-or-prefix hex handle to the unique member it
  names, git-style; an empty, unknown, or ambiguous handle is an error.

## How revocation works

Read revocation rides on the sealed self-root companion (`manifest.FullRootRecord`,
sealed once per authorized device). Revoking a device drops it from the record and
re-seals the companion to the survivors, so the revoked device's ML-KEM key no longer
opens the current root (`manifest.ErrNoSealForKey`). Like every revika revocation this
is **forward-only** — a revoked device keeps whatever plaintext it already downloaded;
the record only governs future bytes. Node-enforced **write** revocation (per-device
signing sub-identities checked at admission) is still planned.

## Serialization

This package holds only the in-memory type and its rules. The JSON codec lives in
`provider` (`EncodeDeviceAuth`/`DecodeDeviceAuth`, which re-derives IDs on decode), and
DHT publish/resolve + validation live in `net` (`DeviceAuthNamespace`,
`deviceAuthValidator`).
