# C-INT-SIG-01 — Double signature

- **Cible** : Clients
- **Catégorie** : Intégrité › Signatures
- **Identifiant** : C-INT-SIG-01

## Description
Un même contenu reçoit deux signatures contradictoires afin de créer une ambiguïté d'autorité.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Impersonation | T1656 | Deux signatures Ed25519 concurrentes brouillent l'identité de l'auteur légitime du contenu. | Faire du ledger SQLite par-owner (index de propriété lié à la pubkey Ed25519) l'unique source d'autorité, refusant toute seconde revendication sur un même contenu. |
| Masquerading | T1036 | L'attaquant présente sa signature comme équivalente à celle de l'owner pour usurper l'autorité sur le contenu. | Lier chaque signature à une capacité signée non ambiguë (localisation manifest + clé encapsulée ML-KEM-768) rattachée à un seul owner. |
| Data Manipulation: Stored Data Manipulation | T1565.001 | La coexistence de deux signatures altère la vérité stockée sur l'intégrité et la provenance du contenu. | Vérifier chaque shard par recomputation du hash de contenu, l'adressage par hash rendant toute revendication contradictoire détectable et rejetable. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Ledger SQLite par-owner + quotas/baux | T1656 | — | SC-6 |
| Signatures / capacités Ed25519 | T1036 | D3-MAN | AU-10 |
| Encapsulation ML-KEM-768 (cap wrapping) | T1036 | D3-MENCR | SC-12 |
| Recompute du hash à la réception | T1565.001 | D3-FH | SI-7 |
| Adressage par hash de contenu | T1565.001 | D3-FH | SI-7 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
