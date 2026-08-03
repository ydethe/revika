# N-DISP-06 — Blocage du gossip

- **Cible** : Nœuds
- **Catégorie** : Disponibilité
- **Identifiant** : N-DISP-06

## Description
Un nœud n'assure pas la propagation des messages de gossip, empêchant la diffusion des informations de contrôle.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Indicator Blocking | T1562.006 | Le nœud bloque le relais des messages de gossip, étouffant la diffusion des informations de contrôle et de santé du réseau. | Propagation redondante via la DHT Kademlia et multiples pairs, de sorte qu'un relais défaillant ne coupe pas la diffusion. |
| Network Denial of Service | T1498 | La non-propagation prive une portion du réseau des mises à jour de contrôle, dégradant la coordination. | Sondes de disponibilité détectant les pairs qui ne relaient pas et re-router via le placement multi-nœuds. |
