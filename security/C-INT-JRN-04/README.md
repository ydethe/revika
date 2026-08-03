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
