# C-INT-SIG-04 — Signature volée

- **Cible** : Clients
- **Catégorie** : Intégrité › Signatures
- **Identifiant** : C-INT-SIG-04

## Description
Une signature, ou la clé qui la produit, est dérobée et réutilisée par un tiers.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Unsecured Credentials | T1552 | La clé de signature Ed25519 mal protégée sur la machine du client est dérobée. | Stocker les clés côté client dans `.revika/keys` avec permissions restreintes et prôner un stockage protégé, réduisant l'exposition de la clé d'owner. |
| Steal Application Access Token | T1528 | Un jeton ou une capacité signée est volé puis rejoué par un tiers. | Limiter la durée de vie (TTL) des jetons/baux signés et permettre leur révocation, bornant la fenêtre d'exploitation d'un vol. |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Le tiers réutilise la signature/clé dérobée pour se faire passer pour l'owner. | Conditionner l'admission des écritures à une preuve de travail argon2id, de sorte que déloger et re-minter une identité bannie coûte du CPU. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Isolation des clés côté client (.revika/keys) | T1552 | — | SC-12 |
| Capacités TTL court + révocation | T1528 | — | AC-3 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1550.001 | — | SC-5 |
| Contrôles CTID (neo4j) | T1552 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-5, CM-6, CM-7, IA-2, IA-3, IA-4, IA-5, RA-5, SA-11, SA-15, SC-4, SC-7, SC-28, SI-2, SI-4, SI-7, SI-12, SI-15 |
| Contrôles CTID (neo4j) | T1528 | — | AC-2, AC-4, AC-5, AC-6, AC-10, CA-7, CM-2, CM-5, CM-6, IA-2, IA-4, IA-5, IA-8, RA-5, SA-11, SA-15, SI-4 |
| Contrôles CTID (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1552 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1528 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1550.001 | D3-OSM | — |
