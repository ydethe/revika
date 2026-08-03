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
| Contrôles CTID (neo4j) | T1499.004 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| Techniques D3FEND (neo4j) | T1499.004 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
