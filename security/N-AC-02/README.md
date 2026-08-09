# N-AC-02 — Granting access without authorisation

- **Target**: Nodes
- **Category**: Access control
- **Identifier**: N-AC-02

## Description
A node serves a shard to a requester who presents no valid authorisation.

## MITRE ATT&CK techniques and defences

| ATT&CK technique | ID | Application to this scenario | Defence measure |
| --- | --- | --- | --- |
| Data from Cloud Storage | T1530 | The attacker retrieves a shard stored in a node without presenting a valid capability, a P2P analogue of direct access to object storage. | Read admission conditioned on presenting a signed capability/token verified against the ledger, with default refusal in the absence of authorisation. |
| Valid Accounts | T1078 | The requester obtains access it should not have, for lack of an authorisation check on the node side. | Authentication of requesters on a self-certifying Ed25519 pubkey and systematic verification of the access right before serving any ciphertext. |

## Defence framework mapping

| Defence measure | ATT&CK technique | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Ed25519 signatures / capabilities | T1078 | D3-MAN | AU-10 |
| Per-owner SQLite ledger + quotas/leases | T1530 | — | SC-6 |
| CTID controls (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-7, SC-28, SC-43, SI-4 |
| CTID controls (neo4j) | T1530 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-7, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-5, CM-6, CM-7, CM-8, IA-2, IA-3, IA-4, IA-5, IA-6, IA-8, RA-5, SC-4, SC-7, SC-28, SI-4, SI-7, SI-12, SI-15 |
| D3FEND techniques (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
| D3FEND techniques (neo4j) | T1530 | D3-AL, D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
