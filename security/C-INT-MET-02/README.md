# C-INT-MET-02 — Modification des timestamps

- **Cible** : Clients
- **Catégorie** : Intégrité › Métadonnées
- **Identifiant** : C-INT-MET-02

## Description
Les horodatages associés aux données du client sont altérés pour fausser l'ordre ou la fraîcheur.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Indicator Removal: Timestomp | T1070.006 | Les horodatages des données sont modifiés pour fausser l'ordre chronologique ou la fraîcheur perçue. | Horloges/nonces/numéros de séquence signés (anti-rejeu) et journal d'audit append-only chaîné rendant toute réécriture temporelle détectable. |
| Data Manipulation: Stored Data Manipulation | T1565.001 | L'altération des métadonnées d'horodatage stockées vise à tromper la logique de version. | Métadonnées d'effacement signées (`stripe.Descriptor`) et manifeste signé Ed25519 figeant l'ordre attendu. |
