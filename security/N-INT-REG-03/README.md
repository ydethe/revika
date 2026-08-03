# N-INT-REG-03 — Omission d'événements

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Registre
- **Identifiant** : N-INT-REG-03

## Description
Un nœud n'inscrit pas certains événements qu'il devrait publier, laissant le registre incomplet.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Indicator Blocking | T1562.006 | Le nœud supprime en amont la publication de certains événements qu'il devrait consigner. | Journal append-only signé et chaîné : l'omission crée des trous détectables via numéros de séquence signés et corroboration croisée entre pairs. |
| Indicator Removal | T1070 | L'absence d'inscription laisse le registre incomplet et masque l'activité réelle du nœud. | Attestations de complétude corroborées par les pairs (index de propriété/stripe du ledger) qui signalent les événements attendus mais absents. |
