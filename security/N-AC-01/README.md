# N-AC-01 — Ignorer une révocation

- **Cible** : Nœuds
- **Catégorie** : Contrôle d'accès
- **Identifiant** : N-AC-01

## Description
Un nœud continue de servir des données à un demandeur dont l'accès a été révoqué.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Valid Accounts | T1078 | Le demandeur exploite une capacité autrefois légitime mais désormais révoquée pour continuer à accéder aux shards. | Révocation propagée et vérifiée à chaque requête, avec capacités signées à TTL court forçant le renouvellement plutôt qu'un droit permanent. |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Un jeton d'accès signé, valide au moment de son émission, est réutilisé après révocation pour justifier l'accès. | Contrôle de l'état de révocation dans le ledger SQLite du nœud avant service, invalidant tout jeton listé même s'il n'est pas encore expiré. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Capacités TTL court + révocation | T1078 | — | AC-3 |
| Ledger SQLite par-owner + quotas/baux | T1550.001 | — | SC-6 |
