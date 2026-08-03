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

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Anti-rejeu nonce/horloge/seq + TTL | T1070.006 | — | SC-23 |
| Journaux append-only chaînés + seq signés | T1070.006 | — | AU-9 |
| Métadonnées d'effacement signées (stripe.Descriptor) | T1565.001 | D3-MAN | SI-7 |
| Manifeste signé Ed25519 versionné | T1565.001 | D3-MAN | SI-7 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
