# N-ORG-SYB-01 — Création de faux nœuds

- **Cible** : Nœuds
- **Catégorie** : Menaces organisationnelles › Sybil / collusion
- **Identifiant** : N-ORG-SYB-01

## Description
Un attaquant crée de nombreuses identités de nœuds pour peser artificiellement sur le réseau.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Establish Accounts | T1585 | L'attaquant fabrique en masse des identités de nœuds pour multiplier son poids apparent dans le réseau. | Identité de stockage auto-certifiante par preuve de travail (argon2id, `internal/cap/pow.go`) : chaque identité coûte du CPU à minter, freinant la fabrication de masse. |
| Create Account | T1136 | Analogue : chaque faux nœud correspond à la création d'une nouvelle identité libp2p/Ed25519. | Admission des écritures conditionnée à une difficulté PoW ≥ celle du nœud, plus quotas par-owner dans le ledger SQLite. |
| Botnet | T1583.005 | Le parc d'identités contrôlées agit comme un botnet pour saturer discovery et placement. | Limites de connexions (`ResourceManager` + `ConnManager`) et rate-limiting par-pair/par-owner keyé sur la pubkey Ed25519 dans `internal/net/defense.go`. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1585, T1136 | — | SC-5 |
| Ledger SQLite par-owner + quotas/baux | T1136 | — | SC-6 |
| ConnectionGater / ResourceManager / ConnManager | T1583.005 | D3-NTF | SC-7 |
| Rate-limiting par-owner (pubkey Ed25519) | T1583.005 | D3-ITF | SC-5 |
