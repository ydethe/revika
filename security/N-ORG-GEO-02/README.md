# N-ORG-GEO-02 — VPN/proxy

- **Target**: Nodes
- **Category**: Organisational threats › Geolocation
- **Identifier**: N-ORG-GEO-02

## Description
A node masks its real location via VPN or proxy, falsifying the perceived geographic diversity.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Multi-hop Proxy | T1090.003 | The node routes through a VPN or a multi-hop proxy to mask its real location and falsify the perceived diversity. | Estimate the position by latency/RTT triangulation and correlation of observed AS/subnet, rather than by the announced address. |
| Virtual Private Server | T1583.003 | The node is hosted on a VPS in order to present a location that appears different from its own. | Detection of known hoster/VPS IP ranges and placement keyed on the actually-measured network diversity. |
| Masquerading | T1036 | The whole simulates a geographic diversity that does not exist physically. | Erasure coding dispersing the shards over distinct owners, so that a fake diversity does not concentrate all `k` at the same real place. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Network-measured placement diversity | T1090.003, T1583.003 | — | SC-36 |
| Placement spread over independent owners | T1036 | — | SC-36 |
| Reed-Solomon k=4/m=2 coding + repair | T1036 | — | SC-36 |
| CTID controls (neo4j) | T1090.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-15 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| D3FEND techniques (neo4j) | T1090.003 | D3-EAL, D3-EDL, D3-ITF, D3-OTF | — |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
