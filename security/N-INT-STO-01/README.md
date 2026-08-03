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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Adressage par hash de contenu | T1565.001 | D3-FH | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1485 | — | SC-36 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| Contrôles CTID (neo4j) | T1485 | — | AC-3, AC-6, CM-2, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| Techniques D3FEND (neo4j) | T1485 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
