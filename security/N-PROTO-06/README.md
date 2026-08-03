# N-PROTO-06 — Désactivation de vérifications

- **Cible** : Nœuds
- **Catégorie** : Menaces protocolaires
- **Identifiant** : N-PROTO-06

## Description
Un nœud désactive localement les contrôles de conformité qu'il est censé appliquer.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Le nœud désactive localement les vérifications de conformité (autorisation, quotas, intégrité) qu'il devrait appliquer. | Sécurité indépendante du bon vouloir du nœud : chiffrement client-side, adressage-hash et effacement Reed-Solomon + réparation neutralisent un nœud qui relâche ses contrôles. |
| Exploitation for Defense Evasion | T1211 | La désactivation des contrôles permet au nœud de contourner les défenses attendues du protocole. | Vérifications critiques rejouées côté User (recomputation de hash, validation des capacités signées) plutôt que déléguées au nœud. |
