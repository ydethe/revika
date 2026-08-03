# N-CONF-03 — Corrélation des métadonnées

- **Cible** : Nœuds
- **Catégorie** : Confidentialité › Données
- **Identifiant** : N-CONF-03

## Description
Le recoupement des métadonnées visibles côté nœud (identifiants de contenu, propriétaires, tailles, horodatages) permet de reconstituer des liens entre shards, et donc entre fichiers ou utilisateurs.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data from Information Repositories | T1213 | Le nœud interroge son ledger SQLite (CID, propriétaires, tailles, horodatages) pour corréler les shards entre eux. | Adressage par hash de contenu rendant les CID opaques et ledger limité au strict nécessaire (propriété/lease/quota), sans lien vers le fichier logique. |
| Automated Collection | T1119 | Collecte et recoupement automatisés des métadonnées de plusieurs shards pour inférer des relations. | Rate-limiting par-owner clé sur la pubkey Ed25519 (`internal/net/defense.go`) plafonnant le volume de métadonnées observable par un pair. |
| Gather Victim Org Information | T1591 | Reconstitution de liens fichiers ↔ utilisateurs à partir des métadonnées agrégées. | Codage d'effacement + placement réparti sur nœuds indépendants : aucun nœud ne voit l'ensemble des shards d'un même fichier. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Adressage par hash de contenu | T1213 | D3-FH | SI-7 |
| Ledger SQLite par-owner + quotas/baux | T1213 | — | SC-6 |
| Rate-limiting par-owner (pubkey Ed25519) | T1119 | D3-ITF | SC-5 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1591 | — | SC-36 |
| Placement réparti sur owners indépendants | T1591 | — | SC-36 |
| Contrôles CTID (neo4j) | T1213 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-16, AC-17, AC-21, AC-23, CA-7, CM-2, CM-3, CM-5, CM-6, CM-7, CM-8, IA-2, IA-4, IA-8, RA-5, SC-28, SC-37, SI-4 |
| Contrôles CTID (neo4j) | T1119 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, SC-4, SC-36, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1213 | D3-EAL, D3-EDL, D3-ITF, D3-JFAPA, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-RAPA, D3-UAP, D3-UDTA | — |
| Techniques D3FEND (neo4j) | T1119 | D3-OSM | — |
