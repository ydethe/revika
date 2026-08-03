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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| ConnectionGater / ResourceManager / ConnManager | T1499 | D3-NTF | SC-7 |
| Rate-limiting par-owner (pubkey Ed25519) | T1499.001 | D3-ITF | SC-5 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1499.001 | — | SC-5 |
| Ledger SQLite par-owner + quotas/baux | T1498 | — | SC-6 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1498 | — | SC-36 |
| Contrôles CTID (neo4j) | T1499 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| Contrôles CTID (neo4j) | T1499.001 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| Contrôles CTID (neo4j) | T1498 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-15 |
| Techniques D3FEND (neo4j) | T1499 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
| Techniques D3FEND (neo4j) | T1499.001 | D3-EAL, D3-EDL, D3-OSM, D3-OTF | — |
| Techniques D3FEND (neo4j) | T1498 | D3-EAL, D3-EDL, D3-ITF, D3-OTF | — |
