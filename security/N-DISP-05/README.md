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
