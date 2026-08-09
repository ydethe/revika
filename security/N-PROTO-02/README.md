# N-PROTO-02 — Eclipse attack

- **Target**: Nodes
- **Category**: Protocol threats
- **Identifier**: N-PROTO-02

## Description
A node or a group monopolises a victim's connections to control its view of the network and isolate it from honest peers.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Adversary-in-the-Middle | T1557 | By monopolising the victim's connections, the attacker interposes itself between the victim and the rest of the network (Eclipse attack). | Diversification of connections and of the Kademlia buckets of the `/revika` DHT, anchoring on trusted bootstraps and `ConnManager` maintaining links to varied peers. |
| Rogue Domain Controller | T1207 | Fake peers saturate the victim's routing table to dominate its view of the network. | Self-certifying identities by proof of work (argon2id) making mass peer creation more expensive and `ConnectionGater` filtering suspicious peers/subnets. |
| Establish Accounts | T1585 | The attacker mass-creates node identities to populate the victim's surroundings (Sybil). | Anti-Sybil brake via PoW on the storage identity and per-owner rate-limiting keyed on the Ed25519 pubkey. |
| Acquire Infrastructure: Botnet | T1583.005 | A set of controlled nodes is mobilised to surround the victim. | `ResourceManager`/`ConnManager` connection limits and the `ConnectionGater`'s static blocklist capping a single actor's hold. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| DHT /revika + peer diversity | T1557 | — | SC-36 |
| ConnectionGater / ResourceManager / ConnManager | T1207, T1583.005 | D3-NTF | SC-7 |
| Self-certifying argon2id PoW identity (anti-Sybil) | T1207, T1585 | — | SC-5 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1585 | D3-ITF | SC-5 |
| CTID controls (neo4j) | T1557 | — | AC-3, AC-4, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, SC-4, SC-7, SC-8, SC-23, SC-46, SI-3, SI-4, SI-7, SI-12, SI-15 |
| D3FEND techniques (neo4j) | T1557 | D3-EAL, D3-EDL, D3-FA, D3-ITF, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
