# N-CONF-01 — Lecture non autorisée des shards stockés

- **Cible** : Nœuds
- **Catégorie** : Confidentialité › Données
- **Identifiant** : N-CONF-01

## Description
Un nœud (ou un attaquant ayant accès à son disque) tente de lire le contenu des shards qu'il héberge pour en extraire des informations exploitables, alors qu'il n'est censé stocker que du ciphertext opaque adressé par hash de contenu.
