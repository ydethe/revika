# C-AC-06 — Partage de droits

- **Cible** : Clients
- **Catégorie** : Contrôle d'accès
- **Identifiant** : C-AC-06

## Description
Un client redistribue à des tiers non autorisés les droits d'accès qui lui ont été conférés.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Use Alternate Authentication Material | T1550 | Le client transmet à un tiers le matériel d'authentification/capacité qu'il détient. | Partage strictement par encapsulation ML-KEM-768 à la pubkey du destinataire (jamais copie du plaintext) et capacités révocables à TTL. |
| Trusted Relationship | T1199 | Le client abuse de la confiance qui lui a été accordée pour propager l'accès hors périmètre. | Journal d'audit append-only signé et chaîné traçant les partages, avec révocation et rotation des capacités concernées. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Encapsulation ML-KEM-768 (cap wrapping) | T1550 | D3-MENCR | SC-12 |
| Capacités TTL court + révocation | T1550 | — | AC-3 |
| Journaux append-only chaînés + seq signés | T1199 | — | AU-9 |
| Contrôles CTID (neo4j) | T1550 | — | AC-2, AC-5, AC-6, CM-5, CM-6, IA-2 |
| Contrôles CTID (neo4j) | T1199 | — | AC-3, AC-4, AC-6, AC-8, CM-6, CM-7, SC-7, SC-46 |
| Techniques D3FEND (neo4j) | T1550 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1199 | D3-EAL, D3-EDL, D3-ITF, D3-LFP, D3-OTF, D3-UAP | — |
