# N-DISP-04 — Ralentissement volontaire

- **Cible** : Nœuds
- **Catégorie** : Disponibilité
- **Identifiant** : N-DISP-04

## Description
Un nœud dégrade délibérément ses temps de réponse pour nuire à la performance globale sans se déclarer hors ligne.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service | T1499 | Analogue P2P : le nœud dégrade volontairement sa latence de service sans se retirer, nuisant à la disponibilité perçue. | Sondes de disponibilité mesurant la latence, avec basculement des lectures vers des pairs plus rapides grâce à la redondance Reed-Solomon. |
| Service Exhaustion Flood | T1499.002 | Le ralentissement simule une saturation de service pour rendre les réponses inexploitables en pratique. | Rate-limiting par-pair / par-owner (clé sur pubkey Ed25519) et `ResourceManager`/`ConnManager` de `internal/net/defense.go` bornant l'impact d'un pair lent. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Sondes + défis de possession | — | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | — | SC-36 |
| Rate-limiting par-owner (pubkey Ed25519) | D3-ITF | SC-5 |
| ConnectionGater / ResourceManager / ConnManager | D3-NTF | SC-7 |
