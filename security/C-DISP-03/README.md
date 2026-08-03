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

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| ConnectionGater / ResourceManager / ConnManager | T1499.004 | D3-NTF | SC-7 |
| Rate-limiting par-owner (pubkey Ed25519) | T1499.003 | D3-ITF | SC-5 |
| Ledger SQLite par-owner + quotas/baux | T1499.003 | — | SC-6 |
| Contrôles CTID (neo4j) | T1499.004 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| Contrôles CTID (neo4j) | T1499.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| Techniques D3FEND (neo4j) | T1499.004 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
| Techniques D3FEND (neo4j) | T1499.003 | D3-EAL, D3-EDL, D3-OSM, D3-OTF | — |
