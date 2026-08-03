# N-AC-02 — Accorder un accès sans autorisation

- **Cible** : Nœuds
- **Catégorie** : Contrôle d'accès
- **Identifiant** : N-AC-02

## Description
Un nœud sert un shard à un demandeur qui ne présente aucune autorisation valide.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data from Cloud Storage | T1530 | L'attaquant récupère un shard stocké dans un nœud sans présenter de capacité valide, en analogue P2P de l'accès direct à un stockage objet. | Admission des lectures conditionnée à la présentation d'une capacité/jeton signé vérifié contre le ledger, refus par défaut en l'absence d'autorisation. |
| Valid Accounts | T1078 | Le demandeur obtient un accès qu'il ne devrait pas avoir, faute de contrôle d'autorisation côté nœud. | Authentification des demandeurs sur pubkey Ed25519 auto-certifiante et vérification systématique du droit d'accès avant tout service de ciphertext. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Signatures / capacités Ed25519 | T1078 | D3-MAN | AU-10 |
| Ledger SQLite par-owner + quotas/baux | T1530 | — | SC-6 |
| Contrôles CTID (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-7, SC-28, SC-43, SI-4 |
| Contrôles CTID (neo4j) | T1530 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-7, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-5, CM-6, CM-7, CM-8, IA-2, IA-3, IA-4, IA-5, IA-6, IA-8, RA-5, SC-4, SC-7, SC-28, SI-4, SI-7, SI-12, SI-15 |
| Techniques D3FEND (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1530 | D3-AL, D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
