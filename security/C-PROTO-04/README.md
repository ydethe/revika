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

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Protocoles versionnés + fail-closed | — | SI-10 |
| ConnectionGater / ResourceManager / ConnManager | D3-NTF | SC-7 |
