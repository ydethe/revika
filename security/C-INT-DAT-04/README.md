# C-INT-DAT-04 — Suppression logique

- **Cible** : Clients
- **Catégorie** : Intégrité › Données
- **Identifiant** : C-INT-DAT-04

## Description
Des données sont marquées supprimées ou rendues inaccessibles côté client sans suppression légitime.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Destruction | T1485 | Un nœud détruit ou marque supprimés des shards sans ordre légitime du propriétaire. | Redondance Reed-Solomon (`m` parités) répartie sur des nœuds indépendants et réparation obligatoire régénérant les shards manquants. |
| Indicator Removal: File Deletion | T1070.004 | Des shards sont effacés du stockage local pour rendre les données inaccessibles. | Baux à TTL et suppression conditionnée à un jeton signé du propriétaire, journal d'audit append-only chaîné détectant les retraits illégitimes. |
| Inhibit System Recovery | T1490 | La mise hors d'accès des shards vise à empêcher la récupération du fichier. | Probes de disponibilité (`internal/repair`) déclenchant la régénération déterministe des shards depuis les survivants. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Codage Reed-Solomon k=4/m=2 + réparation | — | SC-36 |
| Placement réparti sur owners indépendants | — | SC-36 |
| Capacités TTL court + révocation | — | AC-3 |
| Journaux append-only chaînés + seq signés | — | AU-9 |
| Sondes + défis de possession | — | SI-7 |
