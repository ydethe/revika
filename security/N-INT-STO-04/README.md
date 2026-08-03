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

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Adressage par hash de contenu | T1565.001 | D3-FH | SI-7 |
| Recompute du hash à la réception | T1036 | D3-FH | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1036 | — | SC-36 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
