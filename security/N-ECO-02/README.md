# N-ECO-02 — Participer uniquement aux opérations rémunératrices

- **Cible** : Nœuds
- **Catégorie** : Menaces économiques
- **Identifiant** : N-ECO-02

## Description
Un nœud ne prend en charge que les tâches rentables et néglige les obligations non rémunérées (réparation, service à froid).

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Inhibit System Recovery | T1490 | En négligeant la réparation obligatoire, le nœud empêche la régénération des shards et compromet le rétablissement de la redondance. | Réparation obligatoire pilotée par grant signé sur ciphertext déterministe, exécutée depuis d'autres nœuds via le codage d'effacement Reed-Solomon (`k=4`, `m=2`) sans dépendre du nœud défaillant. |
| Service Stop | T1489 | Le nœud refuse sélectivement les opérations non rémunérées (service à froid), arrêtant de fait le service sur une partie des données. | Sondes de disponibilité détectant le non-service, baux (leases) à TTL dans le ledger et re-placement des shards vers des nœuds honorant leurs engagements. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Codage Reed-Solomon k=4/m=2 + réparation | T1490 | — | SC-36 |
| Grant de réparation signé | T1490 | D3-MAN | AC-3 |
| Sondes + défis de possession | T1489 | — | SI-7 |
| Ledger SQLite par-owner + quotas/baux | T1489 | — | SC-6 |
| Placement réparti sur owners indépendants | T1489 | — | SC-36 |
