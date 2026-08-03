# C-DISP-03 — Téléchargements interrompus

- **Cible** : Clients
- **Catégorie** : Disponibilité
- **Identifiant** : C-DISP-03

## Description
Un client initie puis interrompt systématiquement des téléchargements pour gaspiller les ressources des nœuds.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application or System Exploitation | T1499.004 | L'abus du cycle initier/interrompre exploite le protocole de transfert pour gaspiller les ressources. | Borner temps et ressources par requête via `ResourceManager` et clore les transferts inachevés abusifs. |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | La répétition de téléchargements avortés sature la capacité de service des nœuds. | Rate-limiter par-owner (clé sur la pubkey Ed25519) et pénaliser via le ledger les pairs aux transferts répétitivement interrompus. |
