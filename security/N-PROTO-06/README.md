# N-PROTO-06 — Désactivation de vérifications

- **Cible** : Nœuds
- **Catégorie** : Menaces protocolaires
- **Identifiant** : N-PROTO-06

## Description
Un nœud désactive localement les contrôles de conformité qu'il est censé appliquer.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Disable or Modify Tools | T1685 | Le nœud désactive localement les vérifications de conformité (autorisation, quotas, intégrité) qu'il devrait appliquer. | Sécurité indépendante du bon vouloir du nœud : chiffrement client-side, adressage-hash et effacement Reed-Solomon + réparation neutralisent un nœud qui relâche ses contrôles. |
| Exploitation for Defense Evasion | T1211 | La désactivation des contrôles permet au nœud de contourner les défenses attendues du protocole. | Vérifications critiques rejouées côté User (recomputation de hash, validation des capacités signées) plutôt que déléguées au nœud. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Nœud « dumb/untrusted » + re-vérification côté User | — | SA-8 |
| Codage Reed-Solomon k=4/m=2 + réparation | — | SC-36 |
| Recompute du hash à la réception | D3-FH | SI-7 |
