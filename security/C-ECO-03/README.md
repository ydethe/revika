# C-ECO-03 — Création/suppression répétées

- **Cible** : Clients
- **Catégorie** : Menaces économiques
- **Identifiant** : C-ECO-03

## Description
Un client alterne créations et suppressions pour exploiter les coûts asymétriques des opérations.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | Le cycle rapide création/suppression exploite l'asymétrie de coût pour épuiser les nœuds. | Rate-limiting par-owner et quotas/baux TTL du ledger amortissant le churn, avec garbage collection différée. |
| Data Destruction | T1485 | Les suppressions répétées visent à imposer un coût de réparation/nettoyage disproportionné. | Codage d'effacement Reed-Solomon + réparation déterministe sur ciphertext, et journal d'audit append-only signé traçant chaque suppression. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Rate-limiting par-owner (pubkey Ed25519) | T1499.003 | D3-ITF | SC-5 |
| Ledger SQLite par-owner + quotas/baux | T1499.003 | — | SC-6 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1485 | — | SC-36 |
| Journaux append-only chaînés + seq signés | T1485 | — | AU-9 |
