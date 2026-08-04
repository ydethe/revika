# N-INT-REG-03 — Omission d'événements

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Registre
- **Identifiant** : N-INT-REG-03

## Description
Un nœud n'inscrit pas certains événements qu'il devrait publier, laissant le registre incomplet.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Le nœud supprime en amont la publication de certains événements qu'il devrait consigner. | Journal append-only signé et chaîné : l'omission crée des trous détectables via numéros de séquence signés et corroboration croisée entre pairs. |
| Indicator Removal | T1070 | L'absence d'inscription laisse le registre incomplet et masque l'activité réelle du nœud. | Attestations de complétude corroborées par les pairs (index de propriété/stripe du ledger) qui signalent les événements attendus mais absents. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Journaux append-only chaînés + seq signés | T1562.001 | — | AU-9 |
| Corroboration croisée inter-pairs du ledger | T1070 | — | AU-6 |
| Contrôles CTID (neo4j) | T1070 | — | AC-2, AC-3, AC-5, AC-6, AC-16, AC-17, AC-18, CA-7, CM-2, CM-6, CP-6, CP-7, CP-9, SC-4, SC-36, SI-3, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1070 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
