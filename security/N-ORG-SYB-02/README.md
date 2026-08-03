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

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Codage Reed-Solomon k=4/m=2 + réparation | T1199 | — | SC-36 |
| Placement réparti sur owners indépendants | T1199 | — | SC-36 |
| Sondes + défis de possession | T1585 | — | SI-7 |
| Contrôles CTID (neo4j) | T1199 | — | AC-3, AC-4, AC-6, AC-8, CM-6, CM-7, SC-7, SC-46 |
| Techniques D3FEND (neo4j) | T1199 | D3-EAL, D3-EDL, D3-ITF, D3-LFP, D3-OTF, D3-UAP | — |
