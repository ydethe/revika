# N-ORG-SYB-03 — Censure coordonnée

- **Cible** : Nœuds
- **Catégorie** : Menaces organisationnelles › Sybil / collusion
- **Identifiant** : N-ORG-SYB-03

## Description
Un ensemble de nœuds refuse de concert de servir certaines données ou certains propriétaires.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Service Stop | T1489 | Les nœuds coalisés refusent de concert de servir les shards d'une donnée ou d'un owner ciblé. | Codage d'effacement (`k=4`, `m=2`) avec placement sur de nombreux owners indépendants : tout `k` de shards restants suffit à reconstruire malgré le refus. |
| Network Denial of Service | T1498 | Analogue : la censure coordonnée revient à un déni de service ciblé contre un propriétaire précis. | Découverte via Kademlia DHT sur préfixe privé `/revika` pour localiser des détenteurs alternatifs, et réparation obligatoire régénérant les shards vers d'autres nœuds. |
| Inhibit System Recovery | T1490 | Le refus coordonné peut aussi bloquer la réparation pour empêcher tout rétablissement de la redondance. | Grant de réparation signé exécutable par n'importe quel nœud honnête sur ciphertext déterministe, hors du contrôle des censeurs. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Codage Reed-Solomon k=4/m=2 + réparation | T1489, T1498 | — | SC-36 |
| Placement réparti sur owners indépendants | T1489 | — | SC-36 |
| DHT /revika + diversité des pairs | T1498 | — | SC-36 |
| Grant de réparation signé | T1490 | D3-MAN | AC-3 |
