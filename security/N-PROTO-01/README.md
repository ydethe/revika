# N-PROTO-01 — Injection de faux messages Gossip

- **Cible** : Nœuds
- **Catégorie** : Menaces protocolaires
- **Identifiant** : N-PROTO-01

## Description
Un nœud injecte dans le canal de gossip des messages forgés pour propager de fausses informations de contrôle.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | Des messages de contrôle forgés sont injectés dans le canal de gossip pour altérer la vision partagée du réseau. | Signature Ed25519 de tout message de contrôle et rejet des messages non authentifiés, avec numéros de séquence/nonces anti-rejeu. |
| Application Layer Protocol | T1071 | L'attaquant abuse du protocole libp2p de gossip pour diffuser des informations de contrôle illégitimes. | Protocoles libp2p versionnés sur transport chiffré/authentifié, n'acceptant que des messages conformes émis par des pairs authentifiés. |
| Social Engineering: Impersonation | T1684.001 | Les faux messages se font passer pour émanant d'un pair honnête afin d'être relayés. | Liaison de chaque message à la pubkey auto-certifiante de son émetteur, empêchant l'usurpation d'origine. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Signatures / capacités Ed25519 | T1565.002, T1684.001 | D3-MAN | AU-10 |
| Anti-rejeu nonce/horloge/seq + TTL | T1565.002 | — | SC-23 |
| Protocoles versionnés + fail-closed | T1071 | — | SI-10 |
| Transport libp2p chiffré / authentifié | T1071 | D3-MENCR | SC-8 |
