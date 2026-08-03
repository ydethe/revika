# C-INT-DAT-01 — Envoi de données corrompues

- **Cible** : Clients
- **Catégorie** : Intégrité › Données
- **Identifiant** : C-INT-DAT-01

## Description
Un acteur fait accepter au client des données corrompues qui ne se reconstruisent pas correctement.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | Un shard est corrompu en transit pour que le client reçoive des données qui ne se reconstruisent pas. | Vérification systématique par recomputation du hash de contenu à la réception, rejetant tout shard altéré. |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Un nœud sert un shard corrompu stocké au lieu du ciphertext légitime. | AEAD AES-256-GCM (échec d'authentification à la lecture) combiné à l'adressage par hash détectant la corruption. |
| Inhibit System Recovery | T1490 | La corruption de plusieurs shards vise à empêcher la reconstruction du fichier. | Codage d'effacement Reed-Solomon (`k=4`, `m=2`, tout `k` reconstruit) et réparation obligatoire sur ciphertext déterministe. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Recompute du hash à la réception | T1565.002 | D3-FH | SI-7 |
| Chiffrement client-side AES-256-GCM | T1565.001 | D3-MENCR | SC-28 |
| Adressage par hash de contenu | T1565.001 | D3-FH | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1490 | — | SC-36 |
| Contrôles CTID (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-12 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-36, SI-4, SI-12, SI-16 |
| Contrôles CTID (neo4j) | T1490 | — | AC-2, AC-3, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1565.002 | D3-OSM | — |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| Techniques D3FEND (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
