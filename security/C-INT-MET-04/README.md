# C-INT-MET-04 — Manipulation des versions

- **Cible** : Clients
- **Catégorie** : Intégrité › Métadonnées
- **Identifiant** : C-INT-MET-04

## Description
Le numéro ou la chaîne de version d'un contenu est manipulé pour faire passer une version pour une autre.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Le numéro ou la chaîne de version stockés sont modifiés pour faire passer une version pour une autre. | Manifeste signé Ed25519 par version et pointeurs par hash de contenu, toute manipulation invalidant la signature. |
| Use Alternate Authentication Material | T1550 | Une version antérieure est rejouée comme si elle était courante (analogue de rejeu/rollback). | Numéros de séquence/nonces signés (anti-rejeu) et TTL des jetons rejetant la présentation d'une version périmée. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Manifeste signé Ed25519 versionné | T1565.001 | D3-MAN | SI-7 |
| Adressage par hash de contenu | T1565.001 | D3-FH | SI-7 |
| Anti-rejeu nonce/horloge/seq + TTL | T1550 | — | SC-23 |
| Capacités TTL court + révocation | T1550 | — | AC-3 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| Contrôles CTID (neo4j) | T1550 | — | AC-2, AC-5, AC-6, CM-5, CM-6, IA-2 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| Techniques D3FEND (neo4j) | T1550 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-UAP | — |
