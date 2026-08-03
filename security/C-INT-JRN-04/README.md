# C-INT-JRN-04 — Réémission d'événements

- **Cible** : Clients
- **Catégorie** : Intégrité › Journaux
- **Identifiant** : C-INT-JRN-04

## Description
Des événements de journal déjà consignés sont réémis pour fausser le décompte ou l'historique.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | Analogue de rejeu : des événements déjà consignés sont réémis pour fausser décompte et historique. | Attribuer à chaque événement un nonce/numéro de séquence signé, tout doublon étant détecté et rejeté. |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | La réémission réutilise des messages signés authentiques hors de leur occurrence d'origine. | Chaîner les entrées par hash et horodater/signer chaque occurrence, empêchant l'insertion d'un événement déjà présent dans la chaîne. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Anti-rejeu nonce/horloge/seq + TTL | T1565.002 | — | SC-23 |
| Journaux append-only chaînés + seq signés | T1550.001 | — | AU-9 |
| Contrôles CTID (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-7, SI-12 |
| Contrôles CTID (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1565.002 | D3-OSM | — |
| Techniques D3FEND (neo4j) | T1550.001 | D3-OSM | — |
