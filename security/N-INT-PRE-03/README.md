# N-INT-PRE-03 — Mutualisation de preuves

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Preuves
- **Identifiant** : N-INT-PRE-03

## Description
Plusieurs nœuds partagent une unique copie de la donnée mais présentent chacun une preuve, feignant une redondance qui n'existe pas.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Masquerading | T1036 | Des nœuds distincts se présentent comme des dépositaires indépendants alors qu'ils partagent une seule copie. | Placement par shards erasure-codés distincts (Reed-Solomon k=4/m=2) : chaque nœud doit détenir un shard différent, vérifié par hash, non substituable. |
| Social Engineering: Impersonation | T1684.001 | Analogue : la fausse redondance usurpe le rôle de plusieurs dépositaires indépendants. | Défis de possession simultanés et temporellement contraints sur shards distincts, qu'un stockage partagé unique ne peut satisfaire en parallèle. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Codage Reed-Solomon k=4/m=2 + réparation | T1036 | — | SC-36 |
| Placement réparti sur owners indépendants | T1036 | — | SC-36 |
| Sondes + défis de possession | T1684.001 | — | SI-7 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
