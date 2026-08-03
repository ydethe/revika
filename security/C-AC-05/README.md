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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Capacités TTL court + révocation | T1550.001 | — | AC-3 |
| ConnectionGater / ResourceManager / ConnManager | T1078 | D3-NTF | SC-7 |
| Encapsulation ML-KEM-768 (cap wrapping) | T1078 | D3-MENCR | SC-12 |
| Contrôles CTID (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| Contrôles CTID (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-28, SC-43, SI-4 |
| Techniques D3FEND (neo4j) | T1550.001 | D3-OSM | — |
| Techniques D3FEND (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
