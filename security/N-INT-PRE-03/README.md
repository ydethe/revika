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
