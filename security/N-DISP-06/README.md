# N-DISP-06 — Blocage du gossip

- **Cible** : Nœuds
- **Catégorie** : Disponibilité
- **Identifiant** : N-DISP-06

## Description
Un nœud n'assure pas la propagation des messages de gossip, empêchant la diffusion des informations de contrôle.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Disable or Modify Tools | T1685 | Le nœud bloque le relais des messages de gossip, étouffant la diffusion des informations de contrôle et de santé du réseau. | Propagation redondante via la DHT Kademlia et multiples pairs, de sorte qu'un relais défaillant ne coupe pas la diffusion. |
| Network Denial of Service | T1498 | La non-propagation prive une portion du réseau des mises à jour de contrôle, dégradant la coordination. | Sondes de disponibilité détectant les pairs qui ne relaient pas et re-router via le placement multi-nœuds. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| DHT /revika + diversité des pairs | T1685 | — | SC-36 |
| Sondes + défis de possession | T1498 | — | SI-7 |
| Placement réparti sur owners indépendants | T1498 | — | SC-36 |
