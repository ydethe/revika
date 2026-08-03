# C-PROTO-01 — Non-respect du protocole

- **Cible** : Clients
- **Catégorie** : Menaces protocolaires
- **Identifiant** : C-PROTO-01

## Description
Un client dévie volontairement du protocole attendu pour provoquer un comportement anormal des nœuds.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application or System Exploitation | T1499.004 | La déviation protocolaire vise à provoquer une faute ou un comportement anormal du nœud. | Protocoles libp2p versionnés avec validation stricte des messages (fail-closed) et `ResourceManager`/`ConnManager` bornant l'impact d'un pair fautif. |
| Application Layer Protocol | T1071 | Le client détourne le protocole applicatif revika de son usage prévu. | Protocoles de flux libp2p versionnés et authentifiés, rejetant toute trame non conforme au contrat de version négocié. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Protocoles versionnés + fail-closed | — | SI-10 |
| ConnectionGater / ResourceManager / ConnManager | D3-NTF | SC-7 |
