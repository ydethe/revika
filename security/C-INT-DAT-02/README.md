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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Adressage par hash de contenu | T1565.001 | D3-FH | SI-7 |
| Chiffrement client-side AES-256-GCM | T1565.001 | D3-MENCR | SC-28 |
| Transport libp2p chiffré / authentifié | T1565.002 | D3-MENCR | SC-8 |
| Recompute du hash à la réception | T1565.002 | D3-FH | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1565.002 | — | SC-36 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-36, SI-4, SI-12, SI-16 |
| Contrôles CTID (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-12 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| Techniques D3FEND (neo4j) | T1565.002 | D3-OSM | — |
