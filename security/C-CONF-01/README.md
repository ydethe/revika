# C-CONF-01 — Déduire l'existence de données

- **Cible** : Clients
- **Catégorie** : Confidentialité
- **Identifiant** : C-CONF-01

## Description
Un observateur infère qu'un fichier ou un ensemble de données existe à partir de signaux indirects, sans y avoir accès.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Network Service Discovery | T1046 | L'observateur interroge la DHT `/revika` et les nœuds pour repérer les enregistrements de fourniture révélant l'existence de shards. | Restreindre la découverte au préfixe DHT privé `/revika` et limiter les annonces publiques de fourniture, les shards restant du ciphertext opaque adressé par hash. |
| Network Sniffing | T1040 | L'analyse des flux libp2p (volumes, motifs d'accès) laisse deviner qu'un jeu de données est présent. | Transport libp2p chiffré/authentifié et rate-limiting par-pair (`internal/net/defense.go`) réduisant l'analyse de trafic. |
| Gather Victim Host Information | T1592 | L'attaquant recoupe des indices d'hôte (occupation disque, nombre de shards) pour conclure à l'existence de données. | Quotas par-owner et baux à TTL dans le ledger SQLite normalisant l'empreinte de stockage, sans exposer le contenu. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| DHT /revika + diversité des pairs | — | SC-36 |
| Adressage par hash de contenu | D3-FH | SI-7 |
| Transport libp2p chiffré / authentifié | D3-MENCR | SC-8 |
| Rate-limiting par-owner (pubkey Ed25519) | D3-ITF | SC-5 |
| Ledger SQLite par-owner + quotas/baux | — | SC-6 |
