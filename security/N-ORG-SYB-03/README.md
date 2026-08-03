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
| Contrôles CTID (neo4j) | T1489 | — | AC-2, AC-3, AC-4, AC-5, AC-6, CA-7, CM-5, CM-6, CM-7, IA-2, SC-7, SC-37, SC-46, SI-4 |
| Contrôles CTID (neo4j) | T1498 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-15 |
| Contrôles CTID (neo4j) | T1490 | — | AC-2, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1489 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1498 | D3-EAL, D3-EDL, D3-ITF, D3-OTF | — |
| Techniques D3FEND (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
