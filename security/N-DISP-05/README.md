# N-DISP-05 — Partition réseau

- **Cible** : Nœuds
- **Catégorie** : Disponibilité
- **Identifiant** : N-DISP-05

## Description
Un nœud ou un adversaire réseau provoque ou exploite une partition pour isoler une partie du réseau.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Network Denial of Service | T1498 | L'adversaire coupe ou congestionne les liens pour isoler un sous-ensemble de nœuds du reste du réseau. | Kademlia DHT sur préfixe privé `/revika` avec placement multi-nœuds et NAT traversal libp2p, la redondance Reed-Solomon permettant de servir depuis la partition majoritaire. |
| Adversary-in-the-Middle | T1557 | La partition (analogue d'une éclipse) place l'adversaire en coupure entre segments pour contrôler ou bloquer les échanges. | Transport libp2p chiffré/authentifié et identités auto-certifiées, empêchant l'injection ou l'interception silencieuse malgré l'isolement. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| DHT /revika + diversité des pairs | T1498 | — | SC-36 |
| Placement réparti sur owners indépendants | T1498 | — | SC-36 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1498 | — | SC-36 |
| Transport libp2p chiffré / authentifié | T1557 | D3-MENCR | SC-8 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1557 | — | SC-5 |
| Contrôles CTID (neo4j) | T1498 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-15 |
| Contrôles CTID (neo4j) | T1557 | — | AC-3, AC-4, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, SC-4, SC-7, SC-23, SC-46, SI-3, SI-4, SI-7, SI-12, SI-15 |
| Techniques D3FEND (neo4j) | T1498 | D3-EAL, D3-EDL, D3-ITF, D3-OTF | — |
| Techniques D3FEND (neo4j) | T1557 | D3-EAL, D3-EDL, D3-FA, D3-ITF, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
