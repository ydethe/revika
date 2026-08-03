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

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Journaux append-only chaînés + seq signés | — | AU-9 |
| Adressage par hash de contenu | D3-FH | SI-7 |
| Corroboration croisée inter-pairs du ledger | — | AU-6 |
