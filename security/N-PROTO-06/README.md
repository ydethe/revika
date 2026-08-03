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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Nœud « dumb/untrusted » + re-vérification côté User | T1685, T1211 | — | SA-8 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1685 | — | SC-36 |
| Recompute du hash à la réception | T1685, T1211 | D3-FH | SI-7 |
| Contrôles CTID (neo4j) | T1211 | — | AC-4, AC-6, CA-7, CM-2, CM-6, CM-8, RA-5, RA-10, SC-2, SC-3, SC-7, SC-18, SC-26, SC-29, SC-30, SC-35, SC-39, SI-2, SI-3, SI-4, SI-5 |
| Techniques D3FEND (neo4j) | T1211 | D3-EI, D3-FA, D3-ITF, D3-LFP, D3-NI, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM, D3-SCP, D3-UAP | — |
