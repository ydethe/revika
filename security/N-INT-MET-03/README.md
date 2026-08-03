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

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Journaux append-only chaînés + seq signés | — | AU-9 |
| Anti-rejeu nonce/horloge/seq + TTL | — | SC-23 |
