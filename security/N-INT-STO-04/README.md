# N-INT-STO-04 — Réorganisation locale des données

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Stockage
- **Identifiant** : N-INT-STO-04

## Description
Le nœud réordonne ou remappe localement ses shards de manière à casser l'association attendue entre identifiant et contenu.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Le nœud remappe localement l'index ID→contenu de sorte qu'un identifiant pointe vers un shard qui n'est pas le sien. | Adressage par hash de contenu : l'ID est dérivé du contenu, donc tout remappage produit un shard dont le hash ne correspond pas et qui est rejeté. |
| Masquerading | T1036 | Analogue P2P : un shard est présenté sous l'identifiant d'un autre, se faisant passer pour un contenu qu'il n'est pas. | Recomputation systématique du hash à la lecture + codage d'effacement/réparation basculant sur les répliques erasure valides. |
