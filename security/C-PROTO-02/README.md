# C-PROTO-02 — Messages dans un ordre invalide

- **Cible** : Clients
- **Catégorie** : Menaces protocolaires
- **Identifiant** : C-PROTO-02

## Description
Un client envoie des messages dans un ordre non prévu pour exploiter des états intermédiaires.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application or System Exploitation | T1499.004 | Le désordre des messages vise à exploiter des états intermédiaires non prévus de la machine à états. | Machine à états protocolaire stricte rejetant les transitions hors séquence, avec numéros de séquence signés pour l'anti-rejeu et le suivi d'ordre. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Protocoles versionnés + fail-closed | T1499.004 | — | SI-10 |
| Anti-rejeu nonce/horloge/seq + TTL | T1499.004 | — | SC-23 |
