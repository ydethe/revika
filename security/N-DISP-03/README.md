# N-DISP-03 — Refus de répondre

- **Cible** : Nœuds
- **Catégorie** : Disponibilité
- **Identifiant** : N-DISP-03

## Description
Un nœud ignore les requêtes entrantes, se comportant comme injoignable tout en restant nominalement présent.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service | T1499 | Analogue P2P : le nœud rend son propre point de service indisponible en n'acquittant plus aucune requête. | Sondes de disponibilité et réparation automatique vers des nœuds répondants, la redondance Reed-Solomon absorbant la perte du nœud silencieux. |
| Service Stop | T1489 | Le nœud reste membre du réseau mais cesse de traiter les flux applicatifs entrants. | Suivi des baux/quotas dans le ledger SQLite et déclassement du nœud injoignable au profit d'un placement sur pairs actifs. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Sondes + défis de possession | T1499 | — | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1499 | — | SC-36 |
| Ledger SQLite par-owner + quotas/baux | T1489 | — | SC-6 |
| Placement réparti sur owners indépendants | T1489 | — | SC-36 |
| Contrôles CTID (neo4j) | T1499 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| Contrôles CTID (neo4j) | T1489 | — | AC-2, AC-3, AC-4, AC-5, AC-6, CA-7, CM-5, CM-6, CM-7, IA-2, SC-7, SC-37, SC-46, SI-4 |
| Techniques D3FEND (neo4j) | T1499 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
| Techniques D3FEND (neo4j) | T1489 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
