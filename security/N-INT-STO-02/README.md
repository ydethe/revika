# N-INT-STO-02 — Fourniture d'un shard corrompu

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Stockage
- **Identifiant** : N-INT-STO-02

## Description
À la lecture, le nœud renvoie un shard dont le contenu ne correspond pas à l'identifiant demandé, sabotant la reconstruction erasure-coded.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | Le nœud sert en transit, à la lecture, un contenu falsifié qui ne correspond pas à l'identifiant de shard demandé. | Vérification par recomputation du hash de contenu à la réception : un shard qui ne re-hashe pas vers l'ID demandé est rejeté. |
| Inhibit System Recovery | T1490 | En fournissant des shards corrompus, le nœud cherche à empêcher la reconstruction erasure-coded du fichier. | Codage Reed-Solomon (tout `k` parmi `k+m` reconstruit) + réparation obligatoire : la lecture bascule sur d'autres shards valides et régénère les manquants. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Recompute du hash à la réception | T1565.002 | D3-FH | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1490 | — | SC-36 |
