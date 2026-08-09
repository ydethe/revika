# N-ORG-SYB-01 — Creation of fake nodes

- **Target**: Nodes
- **Category**: Organisational threats › Sybil / collusion
- **Identifier**: N-ORG-SYB-01

## Description
An attacker creates many node identities to artificially weigh on the network.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Establish Accounts | T1585 | The attacker mass-fabricates node identities to multiply their apparent weight in the network. | Self-certifying storage identity by proof of work (argon2id, `internal/cap/pow.go`): each identity costs CPU to mint, slowing mass fabrication. |
| Create Account | T1136 | Analogue: each fake node corresponds to the creation of a new libp2p/Ed25519 identity. | Write admission conditioned on a PoW difficulty ≥ that of the node, plus per-owner quotas in the SQLite ledger. |
| Botnet | T1583.005 | The fleet of controlled identities acts as a botnet to saturate discovery and placement. | Connection limits (`ResourceManager` + `ConnManager`) and per-peer/per-owner rate-limiting keyed on the Ed25519 pubkey in `internal/net/defense.go`. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Self-certifying argon2id PoW identity (anti-Sybil) | T1585, T1136 | — | SC-5 |
| Per-owner SQLite ledger + quotas/leases | T1136 | — | SC-6 |
| ConnectionGater / ResourceManager / ConnManager | T1583.005 | D3-NTF | SC-7 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1583.005 | D3-ITF | SC-5 |
| CTID controls (neo4j) | T1136 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-20, CM-5, CM-6, CM-7, IA-2, IA-5, SC-7, SC-46, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1136 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
