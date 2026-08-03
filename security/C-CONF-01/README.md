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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| DHT /revika + diversité des pairs | T1046 | — | SC-36 |
| Adressage par hash de contenu | T1046 | D3-FH | SI-7 |
| Transport libp2p chiffré / authentifié | T1040 | D3-MENCR | SC-8 |
| Rate-limiting par-owner (pubkey Ed25519) | T1040 | D3-ITF | SC-5 |
| Ledger SQLite par-owner + quotas/baux | T1592 | — | SC-6 |
| Contrôles CTID (neo4j) | T1046 | — | AC-4, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, SC-7, SC-46, SI-3, SI-4 |
| Contrôles CTID (neo4j) | T1040 | — | AC-16, AC-17, AC-18, AC-19, CM-7, IA-2, IA-5, SC-4, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1046 | D3-FA, D3-ITF, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
| Techniques D3FEND (neo4j) | T1040 | D3-OSM | — |
