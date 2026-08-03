# N-DISP-09 — Déconnexion stratégique

- **Cible** : Nœuds
- **Catégorie** : Disponibilité
- **Identifiant** : N-DISP-09

## Description
Un nœud se déconnecte aux moments critiques (audits, réparations) pour échapper à ses obligations tout en restant nominalement membre.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Disable or Modify Tools | T1685 | Le nœud se déconnecte pendant audits/réparations pour se soustraire à la collecte de preuves de conservation. | Journaux d'audit append-only, signés et chaînés (hash-chain) horodatant l'indisponibilité aux fenêtres critiques, exploitables a posteriori. |
| Service Stop | T1489 | Le nœud suspend son service aux moments d'audit/réparation tout en restant nominalement membre. | Sondes de disponibilité répétées à des instants imprévisibles et réparation vers des pairs disponibles grâce à la redondance Reed-Solomon. |
| Inhibit System Recovery | T1490 | L'absence pendant les réparations empêche la régénération de la redondance du stripe. | Grant de réparation signé permettant à d'autres nœuds de régénérer les shards sans le participant absent. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Journaux append-only chaînés + seq signés | T1685 | — | AU-9 |
| Sondes + défis de possession | T1489 | — | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1489 | — | SC-36 |
| Grant de réparation signé | T1490 | D3-MAN | AC-3 |
| Contrôles CTID (neo4j) | T1489 | — | AC-2, AC-3, AC-4, AC-5, AC-6, CA-7, CM-5, CM-6, CM-7, IA-2, SC-7, SC-37, SC-46, SI-4 |
| Contrôles CTID (neo4j) | T1490 | — | AC-2, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1489 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
