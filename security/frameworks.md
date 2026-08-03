# Correspondance des mesures de défense avec les cadres reconnus

Ce document est la **source unique de vérité** reliant chaque *primitive de défense*
récurrente de revika à :

- une technique défensive **MITRE D3FEND** (cadre *primaire* : dual défensif d'ATT&CK, au
  grain du mécanisme) ;
- un contrôle **NIST SP 800-53 Rev 5** (cadre *secondaire / de complétude* : capte ce que
  D3FEND ne couvre pas, p. ex. le stockage réparti erasure-coded via SC-36).

Chaque fiche `security/<ID>/README.md` porte, sous sa table ATT&CK, une table compacte
`## Correspondance cadres de défense` dont les colonnes `D3FEND` et `NIST 800-53` **reprennent
exactement** les identifiants ci-dessous. Une même primitive reçoit donc toujours les mêmes IDs.

- `—` : le cadre n'a pas de technique/contrôle correspondant (choix état de l'art P2P assumé,
  cf. [Architecture.md](../Architecture.md)), ce n'est pas une erreur de mapping.
- Tous les IDs (ATT&CK, D3FEND, NIST) sont **validés en CI** par `tools/check_attack_ids.py`
  contre les référentiels officiels.

## Table maîtresse

| # | Primitive de défense (libellé fiche) | D3FEND | NIST 800-53 | Justification |
| --- | --- | --- | --- | --- |
| P1 | Chiffrement client-side AES-256-GCM | D3-MENCR | SC-28 | Chiffrement AEAD du contenu côté User avant émission ; les nœuds ne stockent que du ciphertext au repos. Compl. SC-13. |
| P2 | Encapsulation ML-KEM-768 (cap wrapping) | D3-MENCR | SC-12 | KEM-DEM PQC encapsulant la clé AES vers la pubkey du destinataire ; établissement/gestion de clé, jamais côté nœud. Compl. SC-13. |
| P3 | Signatures / capacités Ed25519 | D3-MAN | AU-10 | Authentification de message par signature ; non-répudiation de l'émetteur. Compl. SI-7, IA-5. |
| P4 | Adressage par hash de contenu | D3-FH | SI-7 | Intégrité par empreinte : toute altération casse la correspondance CID↔contenu. D3-FH = fit partiel (hachage). |
| P5 | Recompute du hash à la réception | D3-FH | SI-7 | Vérification d'intégrité avant service/déchiffrement. D3-FH = fit partiel. |
| P6 | Codage Reed-Solomon k=4/m=2 + réparation | — | SC-36 | Traitement/stockage réparti tolérant aux pertes ; réparation = reconstitution. Compl. CP-10. D3FEND ne modélise pas l'erasure coding. |
| P7 | Journaux append-only chaînés + seq signés | — | AU-9 | Protection de l'information d'audit contre réécriture/omission. Compl. AU-10. |
| P8 | Anti-rejeu nonce/horloge/seq + TTL | — | SC-23 | Authenticité de session/échange : rejet des messages rejoués ou hors fenêtre. |
| P9 | Identité auto-certifiante PoW argon2id (anti-Sybil) | — | SC-5 | Admission des écritures conditionnée à une PoW : renchérit floods et création massive d'identités (défense de disponibilité). Ancrage approximatif — l'anti-Sybil P2P proprement dit reste hors cadres. |
| P10 | Rate-limiting par-owner (pubkey Ed25519) | D3-ITF | SC-5 | Filtrage/plafonnement du trafic entrant par identité ; protection anti-DoS. |
| P11 | ConnectionGater / ResourceManager / ConnManager | D3-NTF | SC-7 | Filtrage de trafic + blocklist par pair/sous-réseau ; protection de périmètre. Compl. SC-5. |
| P12 | Capacités TTL court + révocation | — | AC-3 | Renouvellement/révocation forçant la ré-autorisation ; application d'accès. Compl. IA-5. |
| P13 | Ledger SQLite par-owner + quotas/baux | — | SC-6 | Quotas et baux TTL bornant les ressources par owner ; arbitre unique de propriété. Compl. AC-3. |
| P14 | Sondes + défis de possession | — | SI-7 | Vérification d'intégrité/possession par challenge-response ; déclenche la réparation. Compl. CP-10. |
| P15 | DHT `/revika` + diversité des pairs | — | SC-36 | Découverte/propagation redondante répartie ; pas de point unique. |
| P16 | Placement réparti sur owners indépendants | — | SC-36 | Répartition sur pubkeys distinctes ; aucun sous-ensemble < k ne compromet. |
| P17 | Transport libp2p chiffré / authentifié | D3-MENCR | SC-8 | Confidentialité + intégrité en transit ; pairs authentifiés. |
| P18 | Protocoles versionnés + fail-closed | — | SI-10 | Validation stricte des entrées/transitions ; rejet par défaut du non-spécifié. Compl. SC-7. |
| P19 | Manifeste signé Ed25519 versionné | D3-MAN | SI-7 | Authentification + intégrité du manifeste ; le numéro de version détecte le rollback. Compl. AU-10. |
| P20 | Grant de réparation signé | D3-MAN | AC-3 | Autorisation signée de reconstruction sur ciphertext déterministe. |
| P21 | Métadonnées d'effacement signées (`stripe.Descriptor`) | D3-MAN | SI-7 | Descripteur de stripe signé ; falsification invalide la signature. |
| P22 | Diversité de placement mesurée par le réseau | — | SC-36 | Diversité géo/topologique dérivée de sondes RTT/AS observés, imposée au placement. |
| P23 | Nœud « dumb/untrusted » + re-vérification côté User | — | SA-8 | Principe d'ingénierie : la sécurité ne dépend pas du bon comportement du nœud. Compl. SI-7. |
| P24 | Isolation des clés côté client (`.revika/keys`) | — | SC-12 | Clés jamais transmises hors machine ; permissions restreintes. Compl. SC-28. |
| P25 | Chunking taille fixe / normalisation des shards | — | SC-4 | Normalisation limitant l'analyse de corrélation/trafic sur les ressources partagées. |
| P26 | Build reproductible / chaîne d'appro. épinglée | — | SR-4 | Provenance et pinning (toolchain `go 1.26`, dépendances). Compl. SR-11. |
| P27 | Corroboration croisée inter-pairs du ledger | — | AU-6 | Réconciliation/attestations corroborées entre pairs contre l'équivocation. Compl. AU-9. |

## Légende D3FEND

| ID | Technique | Tactique |
| --- | --- | --- |
| D3-MENCR | Message Encryption | Harden |
| D3-FE | File Encryption | Harden |
| D3-MAN | Message Authentication | Harden |
| D3-FH | File Hashing | Detect |
| D3-NTF | Network Traffic Filtering | Isolate |
| D3-ITF | Inbound Traffic Filtering | Isolate |

## Légende NIST SP 800-53 Rev 5

| ID | Contrôle |
| --- | --- |
| AC-3 | Access Enforcement |
| AU-6 | Audit Record Review, Analysis, and Reporting |
| AU-9 | Protection of Audit Information |
| AU-10 | Non-repudiation |
| CP-10 | System Recovery and Reconstitution |
| IA-5 | Authenticator Management |
| SA-8 | Security and Privacy Engineering Principles |
| SC-4 | Information in Shared System Resources |
| SC-5 | Denial-of-Service Protection |
| SC-6 | Resource Availability |
| SC-7 | Boundary Protection |
| SC-8 | Transmission Confidentiality and Integrity |
| SC-12 | Cryptographic Key Establishment and Management |
| SC-13 | Cryptographic Protection |
| SC-23 | Session Authenticity |
| SC-28 | Protection of Information at Rest |
| SC-36 | Distributed Processing and Storage |
| SI-7 | Software, Firmware, and Information Integrity |
| SI-10 | Information Input Validation |
| SR-4 | Provenance |
| SR-11 | Component Authenticity |

## Angles morts assumés

- **Confidentialité par erasure coding** (P6/P16) : les cadres traitent le fragmentaire comme de
  la *disponibilité* (SC-36), pas de la *confidentialité* — c'est bien une confidentialité par
  fragmentation, propre à revika.
- **Anti-Sybil par preuve de travail** (P9) : aucun contrôle NIST/technique D3FEND dédié ;
  SC-5 n'en capte que le volet anti-flood. Relève des couches anti-Sybil/réputation/économiques
  encore différées (cf. Architecture.md §5).
