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

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Adressage par hash de contenu | T1565.001 | D3-FH | SI-7 |
| Manifeste signé Ed25519 versionné | T1565.001 | D3-MAN | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1490 | — | SC-36 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| Contrôles CTID (neo4j) | T1490 | — | AC-2, AC-3, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| Techniques D3FEND (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
