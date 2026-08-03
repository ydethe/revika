# C-INT-MET-01 — Falsification

- **Cible** : Clients
- **Catégorie** : Intégrité › Métadonnées
- **Identifiant** : C-INT-MET-01

## Description
Les métadonnées d'un manifeste client (structure, clés, pointeurs) sont falsifiées pour tromper la reconstruction ou l'accès.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | La structure, les clés ou les pointeurs du manifeste sont modifiés pour détourner la reconstruction ou l'accès. | Manifeste signé Ed25519 avec pointeurs de shards par hash de contenu, toute falsification invalidant la signature ou la vérification de hash. |
| Masquerading | T1036 | Un manifeste falsifié se fait passer pour un manifeste légitime afin de tromper le client. | Capacité de lecture (localisation manifeste + clé encapsulée ML-KEM-768) liée à la pubkey du destinataire, empêchant l'acceptation d'un manifeste non authentifié. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Manifeste signé Ed25519 versionné | T1565.001 | D3-MAN | SI-7 |
| Adressage par hash de contenu | T1565.001 | D3-FH | SI-7 |
| Encapsulation ML-KEM-768 (cap wrapping) | T1036 | D3-MENCR | SC-12 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
