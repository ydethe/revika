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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Codage Reed-Solomon k=4/m=2 + réparation | T1485 | — | SC-36 |
| Placement réparti sur owners indépendants | T1485 | — | SC-36 |
| Capacités TTL court + révocation | T1070.004 | — | AC-3 |
| Journaux append-only chaînés + seq signés | T1070.004 | — | AU-9 |
| Sondes + défis de possession | T1490 | — | SI-7 |
| Contrôles CTID (neo4j) | T1485 | — | AC-3, AC-6, CM-2, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| Contrôles CTID (neo4j) | T1490 | — | AC-2, AC-3, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4 |
| Techniques D3FEND (neo4j) | T1485 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
