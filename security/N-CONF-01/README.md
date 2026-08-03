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
| Contrôles CTID (neo4j) | T1005 | — | AC-2, AC-3, AC-6, AC-16, AC-23, CM-12, CP-9, SA-8, SC-13, SC-38, SI-3, SI-4 |
| Contrôles CTID (neo4j) | T1530 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-7, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-5, CM-6, CM-7, CM-8, IA-2, IA-3, IA-4, IA-5, IA-6, IA-8, RA-5, SC-4, SC-7, SC-28, SI-4, SI-7, SI-12, SI-15 |
| Contrôles CTID (neo4j) | T1119 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, SC-4, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1005 | D3-EAL, D3-EDL, D3-FA, D3-JFAPA, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-RAPA, D3-UAP, D3-UDTA | — |
| Techniques D3FEND (neo4j) | T1530 | D3-AL, D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1119 | D3-OSM | — |
