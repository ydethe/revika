# N-DISP-02 — Refus de fournir un shard

- **Cible** : Nœuds
- **Catégorie** : Disponibilité
- **Identifiant** : N-DISP-02

## Description
Un nœud détient un shard mais refuse de le servir à un client légitime.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Service Stop | T1489 | Analogue P2P : le nœud interrompt sélectivement le service de lecture d'un shard qu'il détient pourtant. | Redondance Reed-Solomon permettant de reconstruire à partir de tout autre sous-ensemble de `k` shards sans dépendre du nœud fautif. |
| Inhibit System Recovery | T1490 | Le refus de servir vise à bloquer la reconstruction du fichier côté client. | Sondes de disponibilité qui requalifient le nœud comme défaillant et déclenchent la réparation vers d'autres nœuds. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Codage Reed-Solomon k=4/m=2 + réparation | T1489 | — | SC-36 |
| Sondes + défis de possession | T1490 | — | SI-7 |
