# N-INT-REG-01 — Double publication

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Registre
- **Identifiant** : N-INT-REG-01

## Description
Un nœud publie deux versions divergentes d'un même enregistrement dans le registre distribué pour créer une incohérence exploitable.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Stored Data Manipulation | T1565.001 | Le nœud inscrit deux valeurs contradictoires pour la même entrée afin d'altérer l'état cohérent du registre. | Chaque entrée est signée Ed25519 et chaînée par hash (append-only), rendant toute équivocation détectable par comparaison des chaînes entre nœuds. |
| Rogue Domain Controller | T1207 | Analogue P2P : le nœud se comporte en pair illégitime diffusant des enregistrements « autoritaires » divergents. | Adressage par hash de contenu + réconciliation croisée du ledger SQLite entre pairs, qui rejette les publications conflictuelles non-monotones. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Journaux append-only chaînés + seq signés | T1565.001 | — | AU-9 |
| Adressage par hash de contenu | T1207 | D3-FH | SI-7 |
| Corroboration croisée inter-pairs du ledger | T1207 | — | AU-6 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-7, SI-12, SI-16 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
