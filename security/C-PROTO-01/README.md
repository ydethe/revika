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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Protocoles versionnés + fail-closed | T1499.004, T1071 | — | SI-10 |
| ConnectionGater / ResourceManager / ConnManager | T1499.004 | D3-NTF | SC-7 |
| Contrôles CTID (neo4j) | T1499.004 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| Contrôles CTID (neo4j) | T1071 | — | AC-4, CA-7, CM-2, CM-6, CM-7, SC-7, SC-10, SC-20, SC-21, SC-22, SC-23, SC-31, SC-37, SI-3, SI-4 |
| Techniques D3FEND (neo4j) | T1499.004 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
| Techniques D3FEND (neo4j) | T1071 | D3-FA, D3-ITF, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
