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
