# C-AC-05 — Contournement d'une révocation

- **Cible** : Clients
- **Catégorie** : Contrôle d'accès
- **Identifiant** : C-AC-05

## Description
Un client dont l'accès a été révoqué contourne la révocation pour continuer d'accéder aux données.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Le client continue de présenter un jeton/capacité malgré la révocation. | Jetons signés à TTL court forçant un renouvellement fréquent, couplés à une révocation effective côté nœud. |
| Valid Accounts | T1078 | Le client réutilise d'anciennes accréditations censées être invalidées. | Blocklist du `ConnectionGater` par pubkey Ed25519 du propriétaire et re-encapsulation (rotation) des capacités partagées après révocation. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Capacités TTL court + révocation | — | AC-3 |
| ConnectionGater / ResourceManager / ConnManager | D3-NTF | SC-7 |
| Encapsulation ML-KEM-768 (cap wrapping) | D3-MENCR | SC-12 |
