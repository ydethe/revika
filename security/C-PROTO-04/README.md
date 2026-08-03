# C-PROTO-04 — Exploitation de comportements indéfinis

- **Cible** : Clients
- **Catégorie** : Menaces protocolaires
- **Identifiant** : C-PROTO-04

## Description
Un client cible des cas non spécifiés du protocole pour obtenir un avantage ou provoquer une faute.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application or System Exploitation | T1499.004 | Le client sollicite des cas non spécifiés du protocole pour déclencher un comportement exploitable. | Rejet par défaut (fail-closed) de tout cas non couvert par la spécification, protocoles versionnés et `ResourceManager` bornant les ressources engagées. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Protocoles versionnés + fail-closed | T1499.004 | — | SI-10 |
| ConnectionGater / ResourceManager / ConnManager | T1499.004 | D3-NTF | SC-7 |
| Contrôles CTID (neo4j) | T1499.004 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-4, SI-15 |
| Techniques D3FEND (neo4j) | T1499.004 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
