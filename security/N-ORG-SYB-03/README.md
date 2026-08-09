# N-ORG-SYB-03 — Coordinated censorship

- **Target**: Nodes
- **Category**: Organisational threats › Sybil / collusion
- **Identifier**: N-ORG-SYB-03

## Description
A set of nodes refuses in concert to serve certain data or certain owners.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Service Stop | T1489 | The coalesced nodes refuse in concert to serve the shards of a targeted data item or owner. | Erasure coding (`k=4`, `m=2`) with placement over many independent owners: any `k` of remaining shards suffices to reconstruct despite the refusal. |
| Network Denial of Service | T1498 | Analogue: coordinated censorship amounts to a targeted denial of service against a specific owner. | Discovery via Kademlia DHT on the private `/revika` prefix to locate alternative holders, and mandatory repair regenerating the shards to other nodes. |
| Inhibit System Recovery | T1490 | The coordinated refusal can also block repair to prevent any restoration of redundancy. | Signed repair grant executable by any honest node on deterministic ciphertext, out of the censors' control. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Reed-Solomon k=4/m=2 coding + repair | T1489, T1498 | — | SC-36 |
| Placement spread over independent owners | T1489 | — | SC-36 |
| DHT /revika + peer diversity | T1498 | — | SC-36 |
| Signed repair grant | T1490 | D3-MAN | AC-3 |
| CTID controls (neo4j) | T1489 | — | AC-2, AC-3, AC-4, AC-5, AC-6, CA-7, CM-5, CM-6, CM-7, IA-2, SC-7, SC-37, SC-46, SI-4 |
| CTID controls (neo4j) | T1498 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-15 |
| CTID controls (neo4j) | T1490 | — | AC-2, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1489 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
| D3FEND techniques (neo4j) | T1498 | D3-EAL, D3-EDL, D3-ITF, D3-OTF | — |
| D3FEND techniques (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
