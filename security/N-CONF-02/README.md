# N-CONF-02 — Access analysis

- **Target**: Nodes
- **Category**: Confidentiality › Data
- **Identifier**: N-CONF-02

## Description
Observing the read/write patterns on the shards (frequency, sequence, size) makes it possible to infer information about the files or a user's activity without ever decrypting the data.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Automated Collection | T1119 | The node logs and automatically collects accesses to derive frequency/sequence/size patterns from them. | Fixed-size chunking + content-hash addressing mask the logical structure and the real size of files behind uniform shards. |
| Data from Local System | T1005 | Exploitation of local access metadata (order and rhythm of reads/writes) as a side channel. | Reed-Solomon erasure coding dispersing accesses across at least `k+m` independent nodes: no node observes the complete sequence of a file. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Fixed-size chunking / shard normalisation | T1119 | — | SC-4 |
| Content-hash addressing | T1119 | D3-FH | SI-7 |
| Distributed placement across independent owners | T1005 | — | SC-36 |
| CTID controls (neo4j) | T1119 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, SC-36, SI-4, SI-12 |
| CTID controls (neo4j) | T1005 | — | AC-2, AC-3, AC-6, AC-16, AC-23, CM-12, CP-9, SA-8, SC-13, SC-28, SC-38, SI-3, SI-4 |
| D3FEND techniques (neo4j) | T1119 | D3-OSM | — |
| D3FEND techniques (neo4j) | T1005 | D3-EAL, D3-EDL, D3-FA, D3-JFAPA, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-RAPA, D3-UAP, D3-UDTA | — |
