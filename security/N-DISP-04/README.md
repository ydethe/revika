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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Sondes + défis de possession | T1499 | — | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1499 | — | SC-36 |
| Rate-limiting par-owner (pubkey Ed25519) | T1499.002 | D3-ITF | SC-5 |
| ConnectionGater / ResourceManager / ConnManager | T1499.002 | D3-NTF | SC-7 |
| Contrôles CTID (neo4j) | T1499 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| Contrôles CTID (neo4j) | T1499.002 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| Techniques D3FEND (neo4j) | T1499 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
| Techniques D3FEND (neo4j) | T1499.002 | D3-EAL, D3-EDL, D3-OSM, D3-OTF | — |
