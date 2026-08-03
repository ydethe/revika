# N-INT-MET-04 — Suppression d'événements locaux

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Métadonnées
- **Identifiant** : N-INT-MET-04

## Description
Le nœud efface des entrées de son journal local de métadonnées pour dissimuler des opérations passées.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Disable or Modify Tools: Clear Linux or Mac System Logs | T1685.006 | Le nœud supprime des entrées de son journal local de métadonnées pour dissimuler des opérations effectuées. | Journaux d'audit append-only, signés et chaînés (hash-chain) : la suppression d'une entrée casse la continuité du chaînage et se détecte. |
| Disable or Modify Tools: Disable or Modify Cloud Log | T1685.002 | Analogue de stockage : le nœud altère la journalisation qui documente son propre comportement pour échapper à l'audit. | Journal chaîné répliqué/vérifiable par les pairs + numéros de séquence signés rendant toute omission visible comme un trou dans la séquence. |
