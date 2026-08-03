# C-DISP-04 — Demandes massives de reconstruction

- **Cible** : Clients
- **Catégorie** : Disponibilité
- **Identifiant** : C-DISP-04

## Description
Un client déclenche des reconstructions erasure-coded en masse pour saturer le calcul et la bande passante.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | Les demandes massives de reconstruction Reed-Solomon saturent CPU et bande passante des nœuds. | Conditionner la réparation à un grant de réparation signé (`stripe`) et rate-limiter les reconstructions par-owner. |
| Resource Hijacking | T1496 | L'attaquant détourne le calcul et la bande passante des nœuds via des reconstructions inutiles. | Encadrer par quotas et baux TTL du ledger, en réservant les reconstructions au processus de réparation légitime. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Grant de réparation signé | T1499.003 | D3-MAN | AC-3 |
| Rate-limiting par-owner (pubkey Ed25519) | T1499.003 | D3-ITF | SC-5 |
| Ledger SQLite par-owner + quotas/baux | T1496 | — | SC-6 |
