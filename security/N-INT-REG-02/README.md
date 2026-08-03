# N-INT-REG-02 — Réécriture du registre

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Registre
- **Identifiant** : N-INT-REG-02

## Description
Un nœud tente de modifier a posteriori des entrées déjà inscrites dans le registre distribué.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Stored Data Manipulation | T1565.001 | Le nœud réécrit des entrées de registre déjà validées pour en changer le contenu historique. | Journal append-only signé et chaîné par hash : toute réécriture rompt la hash-chain et invalide les signatures Ed25519 en aval. |
| Indicator Removal | T1070 | La modification a posteriori vise à effacer ou maquiller la trace d'événements passés. | Réplication signée du ledger entre pairs et vérification de la continuité de la chaîne, empêchant l'acceptation d'une version altérée. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Journaux append-only chaînés + seq signés | T1565.001 | — | AU-9 |
| Corroboration croisée inter-pairs du ledger | T1070 | — | AU-6 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-7, SI-12, SI-16 |
| Contrôles CTID (neo4j) | T1070 | — | AC-2, AC-3, AC-5, AC-6, AC-16, AC-17, AC-18, CA-7, CM-2, CM-6, CP-6, CP-7, CP-9, SC-4, SC-36, SI-3, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| Techniques D3FEND (neo4j) | T1070 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
