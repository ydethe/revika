# C-COL-01 — Collusion entre clients

- **Cible** : Clients
- **Catégorie** : Collusion
- **Identifiant** : C-COL-01

## Description
Plusieurs clients coordonnent leurs actions pour contourner des limites ou fausser des mécanismes.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Create Account | T1136 | Les acteurs créent plusieurs identités clientes coordonnées pour dépasser les limites individuelles (analogue Sybil). | Identité de stockage auto-certifiante par preuve de travail (argon2id), rendant coûteuse la multiplication d'identités. |
| Establish Accounts | T1585 | Les identités sont établies de concert pour fausser des mécanismes reposant sur un décompte par acteur. | Quotas et rate-limiting appliqués par-owner sur la pubkey Ed25519, indépendamment du nombre d'identités. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1136 | — | SC-5 |
| Ledger SQLite par-owner + quotas/baux | T1585 | — | SC-6 |
| Rate-limiting par-owner (pubkey Ed25519) | T1585 | D3-ITF | SC-5 |
| Contrôles CTID (neo4j) | T1136 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-20, CM-5, CM-6, CM-7, IA-2, IA-5, SC-7, SC-46, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1136 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
