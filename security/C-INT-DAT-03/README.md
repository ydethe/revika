# C-INT-DAT-03 — Versions incompatibles

- **Cible** : Clients
- **Catégorie** : Intégrité › Données
- **Identifiant** : C-INT-DAT-03

## Description
Le client se voit présenter un mélange de versions incompatibles d'un même contenu, empêchant une reconstruction cohérente.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Des nœuds servent des shards issus de versions différentes du même contenu, mélangeant des stripes incohérentes. | Adressage par hash de contenu liant chaque shard à sa version exacte, le manifeste signé fixant l'ensemble cohérent à récupérer. |
| Inhibit System Recovery | T1490 | Le mélange de versions empêche le rassemblement de `k` shards compatibles et bloque la reconstruction. | Codage Reed-Solomon avec sélection des `k` shards du hash attendu et réparation déterministe sur ciphertext. |
