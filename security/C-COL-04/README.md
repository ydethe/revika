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
| Social Engineering: Impersonation | T1684.001 | Les faux événements imitent des actions légitimes d'autres acteurs pour tromper le registre. | Événements signés Ed25519 et adressage par hash de contenu, imposant une provenance vérifiable pour chaque entrée. |
