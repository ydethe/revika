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
