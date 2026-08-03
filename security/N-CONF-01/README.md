# N-CONF-01 — Lecture non autorisée des shards stockés

- **Cible** : Nœuds
- **Catégorie** : Confidentialité › Données
- **Identifiant** : N-CONF-01

## Description
Un nœud (ou un attaquant ayant accès à son disque) tente de lire le contenu des shards qu'il héberge pour en extraire des informations exploitables, alors qu'il n'est censé stocker que du ciphertext opaque adressé par hash de contenu.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data from Local System | T1005 | Le nœud lit directement les fichiers de shards présents sur son disque local pour tenter d'en extraire du contenu. | Chiffrement client-side AES-256-GCM avant émission : le nœud ne stocke que du ciphertext opaque, aucune clé n'est présente côté nœud. |
| Data from Cloud Storage | T1530 | Analogue P2P : extraction de données depuis un magasin de blobs distant hébergeant les shards. | Encapsulation de capacités ML-KEM-768 (KEM-DEM, PQC) : la clé de déchiffrement reste côté User et n'atteint jamais le magasin. |
| Automated Collection | T1119 | Le nœud collecte systématiquement l'ensemble des shards qu'il héberge pour les analyser. | Codage d'effacement Reed-Solomon (`k=4`, `m=2`) réparti sur nœuds indépendants : aucun nœud ne détient un fichier entier ni assez de shards pour reconstruire. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Chiffrement client-side AES-256-GCM | T1005 | D3-MENCR | SC-28 |
| Encapsulation ML-KEM-768 (cap wrapping) | T1530 | D3-MENCR | SC-12 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1119 | — | SC-36 |
