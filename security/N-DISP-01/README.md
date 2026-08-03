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

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Codage Reed-Solomon k=4/m=2 + réparation | T1485 | — | SC-36 |
| Ledger SQLite par-owner + quotas/baux | T1070.004 | — | SC-6 |
| Sondes + défis de possession | T1070.004 | — | SI-7 |
| Placement réparti sur owners indépendants | T1490 | — | SC-36 |
| Contrôles CTID (neo4j) | T1485 | — | AC-3, AC-6, CM-2, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| Contrôles CTID (neo4j) | T1490 | — | AC-2, AC-3, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1485 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
