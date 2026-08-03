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

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Encapsulation ML-KEM-768 (cap wrapping) | D3-MENCR | SC-12 |
| Capacités TTL court + révocation | — | AC-3 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | — | SC-5 |
| Journaux append-only chaînés + seq signés | — | AU-9 |
