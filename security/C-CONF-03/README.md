# C-CONF-03 — Observing response times

- **Target**: Clients
- **Category**: Confidentiality
- **Identifier**: C-CONF-03

## Description
Analysing the latencies of client operations reveals information such as cache presence, size, or access path.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Network Sniffing | T1040 | The observer measures shard-request latencies over the libp2p network (a timing side-channel analogue) to infer size and cache. | Encrypted/authenticated transport and parallel retrieval of the `k` Reed-Solomon shards, smoothing the observable response times. |
| Gather Victim Host Information | T1592 | Latency variations reveal the cache state and access path on the host side. | Per-peer rate-limiting (`internal/net/defense.go`) and response normalization, limiting the exploitable timing signal. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Encrypted / authenticated libp2p transport | T1040 | D3-MENCR | SC-8 |
| Reed-Solomon coding k=4/m=2 + repair | T1040 | — | SC-36 |
| Per-owner rate-limiting (Ed25519 pubkey) | T1592 | D3-ITF | SC-5 |
| CTID controls (neo4j) | T1040 | — | AC-16, AC-17, AC-18, AC-19, CM-7, IA-2, IA-5, SC-4, SI-4, SI-7, SI-12 |
| D3FEND techniques (neo4j) | T1040 | D3-OSM | — |
