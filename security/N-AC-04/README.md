# N-AC-04 — Utiliser des permissions obsolètes

- **Cible** : Nœuds
- **Catégorie** : Contrôle d'accès
- **Identifiant** : N-AC-04

## Description
Un nœud s'appuie sur d'anciennes permissions non rafraîchies pour justifier un accès.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Valid Accounts | T1078 | Des permissions obsolètes, jamais réévaluées, servent de base à un accès qui n'est plus légitime. | Capacités et baux à TTL court forçant un rafraîchissement périodique plutôt que la mise en cache d'anciennes autorisations. |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Un jeton signé ancien est réutilisé sans revérification de sa validité courante. | Revalidation à chaque requête de l'état du jeton (signature, TTL, révocation) contre le ledger SQLite du nœud. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Capacités TTL court + révocation | — | AC-3 |
| Ledger SQLite par-owner + quotas/baux | — | SC-6 |
