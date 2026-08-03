# N-CONF-04 — Observation des flux réseau

- **Cible** : Nœuds
- **Catégorie** : Confidentialité › Données
- **Identifiant** : N-CONF-04

## Description
L'analyse du trafic entrant/sortant d'un nœud (volumes, destinations, timing) révèle des informations sur les échanges même lorsque le contenu transporté est chiffré.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Network Sniffing | T1040 | Capture et analyse du trafic entrant/sortant du nœud (volumes, timing) malgré un contenu chiffré. | Transport libp2p chiffré et authentifié ne véhiculant que du ciphertext opaque adressé par hash, sans plaintext ni métadonnée de fichier exploitable. |
| Gather Victim Network Information | T1590 | Collecte des destinations et des débits pour cartographier les échanges du nœud. | NAT traversal libp2p et dispersion des shards par codage d'effacement sur nœuds indépendants réduisant la corrélation flux ↔ fichier. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Transport libp2p chiffré / authentifié | T1040 | D3-MENCR | SC-8 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1590 | — | SC-36 |
| Placement réparti sur owners indépendants | T1590 | — | SC-36 |
