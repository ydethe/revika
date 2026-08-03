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

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Anti-rejeu nonce/horloge/seq + TTL | T1550.001 | — | SC-23 |
| Ledger SQLite par-owner + quotas/baux | T1078 | — | SC-6 |
| Contrôles CTID (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| Contrôles CTID (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-7, SC-28, SC-43, SI-4 |
| Techniques D3FEND (neo4j) | T1550.001 | D3-OSM | — |
| Techniques D3FEND (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
