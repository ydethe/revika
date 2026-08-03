# C-AC-02 — Réutilisation d'un droit expiré

- **Cible** : Clients
- **Catégorie** : Contrôle d'accès
- **Identifiant** : C-AC-02

## Description
Un client réutilise un droit ou un jeton dont la validité a expiré.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Le client rejoue un jeton d'accès dont le TTL est dépassé (analogue P2P du rejeu d'un jeton applicatif). | Jetons d'accès signés à durée de vie limitée (TTL) vérifiée à chaque requête, avec nonces/horloges signés côté nœud pour l'anti-rejeu. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Capacités TTL court + révocation | — | AC-3 |
| Anti-rejeu nonce/horloge/seq + TTL | — | SC-23 |
