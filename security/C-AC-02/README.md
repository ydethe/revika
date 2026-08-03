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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Capacités TTL court + révocation | T1550.001 | — | AC-3 |
| Anti-rejeu nonce/horloge/seq + TTL | T1550.001 | — | SC-23 |
| Contrôles CTID (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1550.001 | D3-OSM | — |
