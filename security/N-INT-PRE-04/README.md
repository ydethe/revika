# N-INT-PRE-04 — Fabrication de preuves sans données

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Preuves
- **Identifiant** : N-INT-PRE-04

## Description
Un nœud calcule ou devine une preuve valide sans jamais avoir stocké la donnée sous-jacente.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Weaken Encryption | T1600 | Le nœud exploite un schéma de preuve faible pour calculer/deviner une preuve valide sans détenir la donnée. | Preuve fondée sur le hash de contenu du shard entier avec défi imprévisible, dont l'espace rend le calcul sans les octets réels infaisable. |
| Masquerading | T1036 | La preuve fabriquée fait passer le nœud pour un dépositaire effectif de la donnée. | Défi-réponse portant sur des positions aléatoires du shard adressé par hash, exigeant la détention complète des octets exacts. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Sondes + défis de possession | T1036 | — | SI-7 |
| Adressage par hash de contenu | T1600 | D3-FH | SI-7 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
