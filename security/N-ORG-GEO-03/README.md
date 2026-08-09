# N-ORG-GEO-03 — Concentration on the same infrastructure

- **Target**: Nodes
- **Category**: Organisational threats › Geolocation
- **Identifier**: N-ORG-GEO-03

## Description
Seemingly distinct nodes are hosted on the same infrastructure, nullifying geographic redundancy.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Server | T1583.004 | Several node identities are acquired and run on the same server/hoster, nullifying geographic redundancy. | Colocation detection by observed subnet/AS via the `ConnectionGater` and latency correlation, to avoid placing several `k` shards on the same infrastructure. |
| Masquerading | T1036 | The colocated nodes present themselves as independent to deceive the distribution policy. | Placement imposing distinct owners (Ed25519 pubkey) and measured network diversity, complemented by erasure-coding tolerance. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| ConnectionGater / ResourceManager / ConnManager | T1583.004 | D3-NTF | SC-7 |
| Network-measured placement diversity | T1583.004, T1036 | — | SC-36 |
| Placement spread over independent owners | T1036 | — | SC-36 |
| Reed-Solomon k=4/m=2 coding + repair | T1036 | — | SC-36 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
