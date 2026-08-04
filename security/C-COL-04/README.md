# C-COL-04 — Création coordonnée de faux événements

- **Cible** : Clients
- **Catégorie** : Collusion
- **Identifiant** : C-COL-04

## Description
Des clients fabriquent de concert de faux événements pour tromper le journal ou le registre.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Les clients insèrent de concert de faux événements dans le journal ou le registre. | Journal d'audit append-only signé et chaîné (hash-chain) : toute insertion ou réécriture rompt la chaîne et est détectée. |
| Impersonation | T1656 | Les faux événements imitent des actions légitimes d'autres acteurs pour tromper le registre. | Événements signés Ed25519 et adressage par hash de contenu, imposant une provenance vérifiable pour chaque entrée. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Journaux append-only chaînés + seq signés | T1565.001 | — | AU-9 |
| Signatures / capacités Ed25519 | T1656 | D3-MAN | AU-10 |
| Adressage par hash de contenu | T1656 | D3-FH | SI-7 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-7, SI-12, SI-16 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
