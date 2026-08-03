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
| Contrôles CTID (neo4j) | T1489 | — | AC-2, AC-3, AC-4, AC-5, AC-6, CA-7, CM-5, CM-6, CM-7, IA-2, SC-7, SC-37, SC-46, SI-4 |
| Contrôles CTID (neo4j) | T1490 | — | AC-2, AC-3, AC-6, CM-2, CM-6, CM-7, CP-2, CP-7, CP-9, CP-10, SI-3, SI-4 |
| Techniques D3FEND (neo4j) | T1489 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-OSM, D3-OTF, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1490 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
