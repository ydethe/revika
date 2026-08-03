# C-COL-03 — Partage de clés

- **Cible** : Clients
- **Catégorie** : Collusion
- **Identifiant** : C-COL-03

## Description
Des clients partagent des clés pour mutualiser indûment des accès ou des identités.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Use Alternate Authentication Material | T1550 | Les clients partagent des clés pour mutualiser des accès hors du cadre prévu. | Partage prévu uniquement par encapsulation ML-KEM-768 à la pubkey du destinataire, capacités révocables à TTL et rotation des clés. |
| Valid Accounts | T1078 | Les clients mutualisent une même identité/clé de stockage pour agir sous une identité partagée. | Identité auto-certifiante liée à une clé Ed25519 unique via preuve de travail, avec journal d'audit signé et chaîné traçant les usages. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Encapsulation ML-KEM-768 (cap wrapping) | T1550 | D3-MENCR | SC-12 |
| Capacités TTL court + révocation | T1550 | — | AC-3 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1078 | — | SC-5 |
| Journaux append-only chaînés + seq signés | T1078 | — | AU-9 |
| Contrôles CTID (neo4j) | T1550 | — | AC-2, AC-5, AC-6, CM-5, CM-6, IA-2 |
| Contrôles CTID (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-7, SC-28, SC-43, SI-4 |
| Techniques D3FEND (neo4j) | T1550 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
