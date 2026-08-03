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

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Sondes + défis de possession | — | SI-7 |
| Adressage par hash de contenu | D3-FH | SI-7 |
