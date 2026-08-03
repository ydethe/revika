# N-DISP-01 — Suppression d'un shard

- **Cible** : Nœuds
- **Catégorie** : Disponibilité
- **Identifiant** : N-DISP-01

## Description
Un nœud efface un shard qu'il s'était engagé à conserver, réduisant la redondance disponible pour la reconstruction.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Destruction | T1485 | Le nœud détruit un shard chiffré confié, amputant la redondance du stripe. | Codage d'effacement Reed-Solomon (`k=4`, `m=2`) + réparation obligatoire sur ciphertext déterministe, régénérant tout shard perdu à son adresse par hash. |
| File Deletion | T1070.004 | La suppression du fichier de shard sur le disque du nœud efface la preuve de conservation. | Baux (leases) à TTL et index de propriété/stripe dans le ledger SQLite, croisés à des sondes de disponibilité qui détectent l'absence du shard. |
| Inhibit System Recovery | T1490 | En abaissant le nombre de shards sous `k`, le nœud vise à empêcher la reconstruction du fichier. | Placement redondant sur nœuds indépendants et déclenchement automatique de la réparation dès qu'une sonde signale une redondance dégradée. |
