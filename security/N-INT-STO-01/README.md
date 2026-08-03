# N-INT-STO-01 — Altération d'un shard

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Stockage
- **Identifiant** : N-INT-STO-01

## Description
Un nœud modifie le contenu d'un shard qu'il héberge, corrompant la donnée qu'il est censé restituer à l'identique (adressée par hash de contenu).

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Le nœud altère au repos le contenu d'un shard qu'il stocke, brisant sa correspondance avec le hash de contenu qui l'adresse. | Adressage par hash de contenu : toute altération est détectée à la lecture par recomputation du hash, disqualifiant le shard corrompu. |
| Data Destruction | T1485 | En corrompant irrémédiablement le shard, le nœud détruit de fait la portion de donnée qu'il devait conserver. | Codage d'effacement Reed-Solomon (`k=4`, `m=2`) + réparation obligatoire sur ciphertext déterministe régénérant le shard perdu depuis les autres. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Adressage par hash de contenu | D3-FH | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | — | SC-36 |
