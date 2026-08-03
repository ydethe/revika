# N-INT-MET-03 — Réécriture de l'historique

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Métadonnées
- **Identifiant** : N-INT-MET-03

## Description
Le nœud reconstruit après coup son historique local de métadonnées pour masquer une action ou en simuler une autre.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Indicator Removal | T1070 | Le nœud réécrit a posteriori son historique de métadonnées pour effacer les traces d'une action ou en fabriquer une autre. | Journaux d'audit append-only, signés et chaînés (hash-chain) : toute réécriture rompt le chaînage et devient détectable. |
| Data Manipulation: Stored Data Manipulation | T1565.001 | La reconstruction de l'historique manipule les enregistrements de métadonnées stockés pour simuler un état passé différent. | Événements horodatés par nonces/numéros de séquence signés : un historique reforgé ne peut reproduire les signatures cohérentes d'origine. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Journaux append-only chaînés + seq signés | T1070 | — | AU-9 |
| Anti-rejeu nonce/horloge/seq + TTL | T1565.001 | — | SC-23 |
| Contrôles CTID (neo4j) | T1070 | — | AC-2, AC-3, AC-5, AC-6, AC-16, AC-17, AC-18, CA-7, CM-2, CM-6, CP-6, CP-7, CP-9, SC-4, SC-36, SI-3, SI-4, SI-7, SI-12 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-7, SI-12, SI-16 |
| Techniques D3FEND (neo4j) | T1070 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
