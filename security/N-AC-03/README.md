# N-AC-03 — Servir des données après expiration

- **Cible** : Nœuds
- **Catégorie** : Contrôle d'accès
- **Identifiant** : N-AC-03

## Description
Un nœud continue de fournir des données au-delà de l'expiration du bail ou du jeton correspondant.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Un jeton d'accès signé arrivé à expiration est rejoué pour prolonger indûment l'accès aux shards. | Vérification stricte du TTL et de l'horodatage signé du jeton à chaque requête, rejet de tout jeton expiré. |
| Valid Accounts | T1078 | Un bail (lease) expiré continue de justifier un accès qui aurait dû cesser. | Expiration des baux gérée par le ledger SQLite avec purge par le GC, refusant le service dès le dépassement du TTL. |
