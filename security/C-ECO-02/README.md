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
