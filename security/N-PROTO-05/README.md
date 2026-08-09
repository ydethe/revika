# N-PROTO-05 — Exploitation of vulnerabilities

- **Target**: Nodes
- **Category**: Protocol threats
- **Identifier**: N-PROTO-05

## Description
An attacker exploits a node implementation flaw to hijack its behaviour.

## MITRE ATT&CK techniques and defences

| ATT&CK Technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Exploitation of Remote Services | T1210 | The attacker remotely exploits an implementation flaw exposed via the node's libp2p protocols. | Versioned libp2p protocols and pure-Go / cgo-free code reducing the attack surface, with `ResourceManager` capping resources per connection. |
| Exploitation for Privilege Escalation | T1068 | The flaw is leveraged to hijack the node's behaviour beyond its normal rights. | Data compartmentalisation on the node side (ciphertext only, no keys): a compromise of the process exposes neither plaintext nor capabilities. |

## Defence framework mapping

| Defence measure | ATT&CK Technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Versioned protocols + fail-closed | T1210 | — | SI-10 |
| ConnectionGater / ResourceManager / ConnManager | T1210 | D3-NTF | SC-7 |
| "Dumb/untrusted" node + User-side re-verification | T1068 | — | SA-8 |
| CTID controls (neo4j) | T1210 | — | AC-2, AC-3, AC-4, AC-5, AC-6, CA-2, CA-7, CM-2, CM-5, CM-6, CM-7, CM-8, IA-2, IA-8, RA-5, RA-10, SC-2, SC-3, SC-18, SC-26, SC-29, SC-30, SC-35, SC-39, SC-46, SI-2, SI-3, SI-4, SI-5, SI-7 |
| CTID controls (neo4j) | T1068 | — | AC-2, AC-4, AC-6, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, RA-10, SC-2, SC-3, SC-7, SC-18, SC-30, SC-39, SI-2, SI-3, SI-4, SI-5, SI-7 |
| D3FEND techniques (neo4j) | T1210 | D3-EAL, D3-EDL, D3-EI, D3-FA, D3-ITF, D3-LAM, D3-LFP, D3-NI, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM, D3-SCP, D3-UAP | — |
| D3FEND techniques (neo4j) | T1068 | D3-EI, D3-FA, D3-ITF, D3-LFP, D3-NI, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM, D3-SCP, D3-UAP | — |
