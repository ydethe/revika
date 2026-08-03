# N-DISP-07 — Saturation CPU, mémoire, disque ou bande passante

- **Cible** : Nœuds
- **Catégorie** : Disponibilité
- **Identifiant** : N-DISP-07

## Description
Un nœud est ciblé (ou se sur-engage) jusqu'à épuisement de ses ressources, le rendant incapable de servir.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service | T1499 | Le nœud est saturé (CPU/mémoire/disque) jusqu'à ne plus pouvoir servir ses shards. | `ResourceManager` + `ConnManager` de `internal/net/defense.go` bornant connexions et ressources, avec `ConnectionGater` (blocklist par pair/sous-réseau). |
| OS Exhaustion Flood | T1499.001 | L'afflux de connexions/requêtes épuise les ressources système du nœud. | Rate-limiting par-pair / par-owner (clé sur pubkey Ed25519) et admission des écritures conditionnée à une preuve de travail (argon2id). |
| Network Denial of Service | T1498 | La saturation de bande passante empêche le nœud d'émettre/recevoir les shards. | Quotas par-owner du ledger SQLite et redondance Reed-Solomon permettant de servir depuis d'autres nœuds pendant la saturation. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| ConnectionGater / ResourceManager / ConnManager | D3-NTF | SC-7 |
| Rate-limiting par-owner (pubkey Ed25519) | D3-ITF | SC-5 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | — | SC-5 |
| Ledger SQLite par-owner + quotas/baux | — | SC-6 |
| Codage Reed-Solomon k=4/m=2 + réparation | — | SC-36 |
