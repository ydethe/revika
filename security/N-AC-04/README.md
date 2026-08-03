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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Capacités TTL court + révocation | T1078 | — | AC-3 |
| Ledger SQLite par-owner + quotas/baux | T1550.001 | — | SC-6 |
| Contrôles CTID (neo4j) | T1078 | — | AC-2, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-7, SC-28, SC-43, SI-4 |
| Contrôles CTID (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1550.001 | D3-OSM | — |
