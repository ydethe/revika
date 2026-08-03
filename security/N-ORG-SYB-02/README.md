# N-ORG-SYB-02 — Collusion entre nœuds

- **Cible** : Nœuds
- **Catégorie** : Menaces organisationnelles › Sybil / collusion
- **Identifiant** : N-ORG-SYB-02

## Description
Plusieurs nœuds coordonnent leurs actions pour tromper les mécanismes de placement, d'audit ou de redondance.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Trusted Relationship | T1199 | Des nœuds en collusion coordonnent leurs réponses pour paraître indépendants aux yeux du placement et de l'audit. | Répartition des shards par codage d'effacement sur des owners distincts (pubkey Ed25519) : aucun sous-ensemble en collusion inférieur à `k` ne compromet la reconstruction. |
| Establish Accounts | T1585 | Les colludeurs entretiennent plusieurs identités coordonnées pour simuler une diversité de redondance. | Sondes de possession indépendantes recomputant le hash de contenu : les colludeurs ne peuvent satisfaire l'audit sans réellement détenir des shards distincts. |
