# N-ORG-GEO-04 — Fictitious geographic distribution

- **Target**: Nodes
- **Category**: Organisational threats › Geolocation
- **Identifier**: N-ORG-GEO-04

## Description
An operator simulates a geographic dispersion of its nodes that does not exist physically.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Masquerading | T1036 | The operator fabricates a fictitious geographic dispersion to satisfy the distribution constraints. | Verify the real dispersion via independent latency/topology probes rather than by the declared locations. |
| Multi-hop Proxy | T1090.003 | Multi-hop proxies make nodes appear at distinct locations that do not exist. | RTT triangulation and AS/subnet correlation to unmask relayed exit points. |
| Virtual Private Server | T1583.003 | Distributed VPS instances simulate a dispersed deployment under the control of a single operator. | Placement keyed on measured network diversity + per-owner quotas, and erasure coding preventing all `k` from residing with the same operator. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Network-measured placement diversity | T1036, T1090.003, T1583.003 | — | SC-36 |
| Per-owner SQLite ledger + quotas/leases | T1583.003 | — | SC-6 |
| Reed-Solomon k=4/m=2 coding + repair | T1583.003 | — | SC-36 |
| CTID controls (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| CTID controls (neo4j) | T1090.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-15 |
| D3FEND techniques (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1090.003 | D3-EAL, D3-EDL, D3-ITF, D3-OTF | — |
