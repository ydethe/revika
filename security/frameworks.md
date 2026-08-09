# Mapping of defence measures to recognised frameworks

This document is the **single source of truth** linking each recurring revika
*defence primitive* to:

- a **MITRE D3FEND** defensive technique (*primary* framework: the defensive dual of ATT&CK, at
  the mechanism granularity);
- a **NIST SP 800-53 Rev 5** control (*secondary / completeness* framework: captures what
  D3FEND does not cover, e.g. erasure-coded distributed storage via SC-36).

Each `security/<ID>/README.md` sheet carries, below its ATT&CK table, a compact
`## Defence framework mapping` table whose `D3FEND` and `NIST 800-53` columns **reproduce
exactly** the identifiers below. A given primitive therefore always receives the same IDs.

- `—`: the framework has no corresponding technique/control (a deliberate state-of-the-art P2P
  choice, cf. [Architecture.md](../Architecture.md)); this is not a mapping error.
- All IDs (ATT&CK, D3FEND, NIST) are **validated in CI** by `tools/check_attack_ids.py`
  against the official reference catalogues.

## Master table

| # | Defence primitive (sheet label) | D3FEND | NIST 800-53 | Rationale |
| --- | --- | --- | --- | --- |
| P1 | Client-side AES-256-GCM encryption | D3-MENCR | SC-28 | AEAD encryption of content on the User side before emission; nodes only store ciphertext at rest. Compl. SC-13. |
| P2 | ML-KEM-768 encapsulation (cap wrapping) | D3-MENCR | SC-12 | PQC KEM-DEM encapsulating the AES key to the recipient's pubkey; key establishment/management, never node-side. Compl. SC-13. |
| P3 | Ed25519 signatures / capabilities | D3-MAN | AU-10 | Message authentication by signature; non-repudiation of the sender. Compl. SI-7, IA-5. |
| P4 | Content-hash addressing | D3-FH | SI-7 | Integrity by fingerprint: any tampering breaks the CID↔content correspondence. D3-FH = partial fit (hashing). |
| P5 | Hash recompute on receipt | D3-FH | SI-7 | Integrity verification before serving/decryption. D3-FH = partial fit. |
| P6 | Reed-Solomon coding k=4/m=2 + repair | — | SC-36 | Loss-tolerant distributed processing/storage; repair = reconstitution. Compl. CP-10. D3FEND does not model erasure coding. |
| P7 | Chained append-only logs + signed seq | — | AU-9 | Protection of audit information against rewriting/omission. Compl. AU-10. |
| P8 | Anti-replay nonce/clock/seq + TTL | — | SC-23 | Session/exchange authenticity: rejection of replayed or out-of-window messages. |
| P9 | Self-certifying PoW argon2id identity (anti-Sybil) | — | SC-5 | Write admission conditioned on a PoW: raises the cost of floods and massive identity creation (availability defence). Approximate anchoring — proper P2P anti-Sybil remains outside the frameworks. |
| P10 | Per-owner rate-limiting (Ed25519 pubkey) | D3-ITF | SC-5 | Filtering/capping of incoming traffic by identity; anti-DoS protection. |
| P11 | ConnectionGater / ResourceManager / ConnManager | D3-NTF | SC-7 | Traffic filtering + peer/subnet blocklist; perimeter protection. Compl. SC-5. |
| P12 | Short-TTL capabilities + revocation | — | AC-3 | Renewal/revocation forcing re-authorisation; access enforcement. Compl. IA-5. |
| P13 | Per-owner SQLite ledger + quotas/leases | — | SC-6 | Quotas and TTL leases bounding resources per owner; sole arbiter of ownership. Compl. AC-3. |
| P14 | Probes + possession challenges | — | SI-7 | Integrity/possession verification by challenge-response; triggers repair. Compl. CP-10. |
| P15 | `/revika` DHT + peer diversity | — | SC-36 | Redundant distributed discovery/propagation; no single point. |
| P16 | Distributed placement across independent owners | — | SC-36 | Distribution across distinct pubkeys; no subset < k compromises anything. |
| P17 | Encrypted / authenticated libp2p transport | D3-MENCR | SC-8 | Confidentiality + integrity in transit; authenticated peers. |
| P18 | Versioned protocols + fail-closed | — | SI-10 | Strict validation of inputs/transitions; default rejection of the unspecified. Compl. SC-7. |
| P19 | Versioned Ed25519-signed manifest | D3-MAN | SI-7 | Manifest authentication + integrity; the version number detects rollback. Compl. AU-10. |
| P20 | Signed repair grant | D3-MAN | AC-3 | Signed authorisation of reconstruction over deterministic ciphertext. |
| P21 | Signed erasure metadata (`stripe.Descriptor`) | D3-MAN | SI-7 | Signed stripe descriptor; tampering invalidates the signature. |
| P22 | Network-measured placement diversity | — | SC-36 | Geo/topological diversity derived from observed RTT/AS probes, enforced on placement. |
| P23 | "dumb/untrusted" node + User-side re-verification | — | SA-8 | Engineering principle: security does not depend on the node behaving correctly. Compl. SI-7. |
| P24 | Client-side key isolation (`.revika/keys`) | — | SC-12 | Keys never transmitted off the machine; restricted permissions. Compl. SC-28. |
| P25 | Fixed-size chunking / shard normalisation | — | SC-4 | Normalisation limiting correlation/traffic analysis over shared resources. |
| P26 | Reproducible build / pinned supply chain | — | SR-4 | Provenance and pinning (`go 1.26` toolchain, dependencies). Compl. SR-11. |
| P27 | Cross-peer corroboration of the ledger | — | AU-6 | Reconciliation/attestations corroborated between peers against equivocation. Compl. AU-9. |

## D3FEND legend

| ID | Technique | Tactic |
| --- | --- | --- |
| D3-MENCR | Message Encryption | Harden |
| D3-FE | File Encryption | Harden |
| D3-MAN | Message Authentication | Harden |
| D3-FH | File Hashing | Detect |
| D3-NTF | Network Traffic Filtering | Isolate |
| D3-ITF | Inbound Traffic Filtering | Isolate |

## NIST SP 800-53 Rev 5 legend

| ID | Control |
| --- | --- |
| AC-3 | Access Enforcement |
| AU-6 | Audit Record Review, Analysis, and Reporting |
| AU-9 | Protection of Audit Information |
| AU-10 | Non-repudiation |
| CP-10 | System Recovery and Reconstitution |
| IA-5 | Authenticator Management |
| SA-8 | Security and Privacy Engineering Principles |
| SC-4 | Information in Shared System Resources |
| SC-5 | Denial-of-Service Protection |
| SC-6 | Resource Availability |
| SC-7 | Boundary Protection |
| SC-8 | Transmission Confidentiality and Integrity |
| SC-12 | Cryptographic Key Establishment and Management |
| SC-13 | Cryptographic Protection |
| SC-23 | Session Authenticity |
| SC-28 | Protection of Information at Rest |
| SC-36 | Distributed Processing and Storage |
| SI-7 | Software, Firmware, and Information Integrity |
| SI-10 | Information Input Validation |
| SR-4 | Provenance |
| SR-11 | Component Authenticity |

## Accepted blind spots

- **Confidentiality by erasure coding** (P6/P16): the frameworks treat fragmentation as
  *availability* (SC-36), not *confidentiality* — yet this really is confidentiality by
  fragmentation, specific to revika.
- **Anti-Sybil by proof of work** (P9): no dedicated NIST control / D3FEND technique;
  SC-5 captures only its anti-flood facet. Belongs to the anti-Sybil/reputation/economic layers
  still deferred (cf. Architecture.md §5).
