# C-INT-DAT-05 — Injection de données malveillantes

- **Cible** : Clients
- **Catégorie** : Intégrité › Données
- **Identifiant** : C-INT-DAT-05

## Description
Un attaquant insère dans le flux du client des données malveillantes destinées à être stockées ou traitées.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | L'attaquant injecte des shards illégitimes dans le flux d'écriture/lecture du client. | Recomputation du hash de contenu à la réception et AEAD AES-256-GCM rejetant tout shard non issu du chiffrement client-side. |
| Exploitation for Client Execution | T1203 | Les données malveillantes injectées visent à être traitées par le client pour déclencher un comportement non voulu. | Traitement des shards comme ciphertext opaque adressé par hash, vérifié avant tout déchiffrement, sans interprétation par les nœuds. |
