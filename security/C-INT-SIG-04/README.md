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
