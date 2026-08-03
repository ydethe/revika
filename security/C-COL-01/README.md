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
