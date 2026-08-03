# C-INT-DAT-02 — Modification non autorisée

- **Cible** : Clients
- **Catégorie** : Intégrité › Données
- **Identifiant** : C-INT-DAT-02

## Description
Les données d'un client sont modifiées sans son autorisation entre l'écriture et la relecture.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Le ciphertext stocké est modifié entre l'écriture et la relecture sans autorisation du propriétaire. | Adressage par hash de contenu et AEAD AES-256-GCM détectant toute modification à la lecture. |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | Les shards sont altérés lors de leur restitution au client. | Transport libp2p authentifié et recomputation du hash à la réception, réparation depuis les shards intacts. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Adressage par hash de contenu | D3-FH | SI-7 |
| Chiffrement client-side AES-256-GCM | D3-MENCR | SC-28 |
| Transport libp2p chiffré / authentifié | D3-MENCR | SC-8 |
| Recompute du hash à la réception | D3-FH | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | — | SC-36 |
