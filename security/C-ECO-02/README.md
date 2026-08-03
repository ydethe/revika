# C-ECO-02 — Multiplication d'opérations

- **Cible** : Clients
- **Catégorie** : Menaces économiques
- **Identifiant** : C-ECO-02

## Description
Un client répète des opérations à grande échelle pour tirer un avantage économique disproportionné.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | La répétition d'opérations à grande échelle sature les nœuds servants. | Rate-limiting par-pair / par-owner (pubkey Ed25519) et limites de connexions `ConnManager`/`ResourceManager`. |
| Resource Hijacking | T1496 | Le client détourne un volume de service disproportionné à son profit. | Quotas et baux TTL du ledger par-owner, avec admission des écritures sous preuve de travail imposant un coût CPU par opération. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Rate-limiting par-owner (pubkey Ed25519) | T1499.003 | D3-ITF | SC-5 |
| ConnectionGater / ResourceManager / ConnManager | T1499.003 | D3-NTF | SC-7 |
| Ledger SQLite par-owner + quotas/baux | T1496 | — | SC-6 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1496 | — | SC-5 |
