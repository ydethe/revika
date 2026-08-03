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
