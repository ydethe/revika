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
