# C-CONF-04 — Collecte d'informations publiques

- **Cible** : Clients
- **Catégorie** : Confidentialité
- **Identifiant** : C-CONF-04

## Description
Un attaquant agrège des informations publiquement disponibles (annonces DHT, clés publiques) pour profiler un client.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Gather Victim Network Information | T1590 | L'attaquant agrège les annonces DHT et pairs observables pour cartographier l'empreinte réseau du client. | Découverte confinée au préfixe DHT privé `/revika` et minimisation des annonces de fourniture publiques. |
| Gather Victim Identity Information | T1589 | Les pubkeys ML-KEM/Ed25519 publiques sont collectées pour rattacher un client à ses activités. | Identités auto-certifiées libp2p dissociées de l'identité réelle, rotation possible des identités de stockage. |
| Network Service Discovery | T1046 | Les requêtes DHT énumèrent les enregistrements de fourniture pour profiler les données rattachées à un client. | Adressage par hash opaque et rate-limiting par-owner sur la pubkey Ed25519 freinant l'énumération. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| DHT /revika + diversité des pairs | T1590 | — | SC-36 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1589 | — | SC-5 |
| Adressage par hash de contenu | T1046 | D3-FH | SI-7 |
| Rate-limiting par-owner (pubkey Ed25519) | T1046 | D3-ITF | SC-5 |
| Contrôles CTID (neo4j) | T1046 | — | AC-4, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, SC-7, SC-46, SI-3, SI-4 |
| Techniques D3FEND (neo4j) | T1046 | D3-FA, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
