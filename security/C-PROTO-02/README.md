# C-PROTO-02 — Messages in an invalid order

- **Target**: Clients
- **Category**: Protocol threats
- **Identifier**: C-PROTO-02

## Description
A client sends messages in an unexpected order to exploit intermediate states.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application or System Exploitation | T1499.004 | The message disordering aims to exploit unexpected intermediate states of the state machine. | Strict protocol state machine rejecting out-of-sequence transitions, with signed sequence numbers for anti-replay and order tracking. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Versioned protocols + fail-closed | T1499.004 | — | SI-10 |
| Anti-replay nonce/clock/seq + TTL | T1499.004 | — | SC-23 |
| CTID controls (neo4j) | T1499.004 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| D3FEND techniques (neo4j) | T1499.004 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
