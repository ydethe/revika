# N-INT-PRE-02 — Réutilisation d'anciennes preuves

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Preuves
- **Identifiant** : N-INT-PRE-02

## Description
Un nœud rejoue une preuve de stockage valide émise précédemment pour prétendre détenir encore la donnée.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Use Alternate Authentication Material | T1550 | Analogue de rejeu : le nœud réémet une preuve de stockage déjà valide pour paraître encore dépositaire. | Défis de possession à nonce aléatoire frais et à TTL, signés, rendant toute preuve antérieure inutilisable pour un nouveau défi. |
| Transmitted Data Manipulation | T1565.002 | La preuve rejouée fausse l'état de disponibilité transmis au vérifieur. | Liaison de chaque preuve à un challenge unique horodaté et signé (Ed25519), vérifiée puis rejetée si déjà consommée dans le ledger. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Sondes + défis de possession | T1550 | — | SI-7 |
| Anti-rejeu nonce/horloge/seq + TTL | T1565.002 | — | SC-23 |
| Contrôles CTID (neo4j) | T1550 | — | AC-2, AC-3, AC-5, AC-6, CM-5, CM-6, IA-2 |
| Contrôles CTID (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1550 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1565.002 | D3-OSM | — |
