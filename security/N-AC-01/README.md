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
| Contrôles CTID (neo4j) | T1078 | — | AC-2, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-7, SC-28, SC-43, SI-4 |
| Contrôles CTID (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1550.001 | D3-OSM | — |
