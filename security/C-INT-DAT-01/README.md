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
