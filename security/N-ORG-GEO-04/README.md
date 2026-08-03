# N-ORG-GEO-04 — Répartition géographique fictive

- **Cible** : Nœuds
- **Catégorie** : Menaces organisationnelles › Géolocalisation
- **Identifiant** : N-ORG-GEO-04

## Description
Un opérateur simule une dispersion géographique de ses nœuds qui n'existe pas physiquement.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Masquerading | T1036 | L'opérateur fabrique une dispersion géographique fictive pour satisfaire les contraintes de répartition. | Vérifier la dispersion réelle par sondes de latence/topologie indépendantes plutôt que par les localisations déclarées. |
| Multi-hop Proxy | T1090.003 | Des proxys multi-sauts font apparaître des nœuds à des localisations distinctes qui n'existent pas. | Triangulation RTT et corrélation d'AS/sous-réseau pour démasquer des points de sortie relayés. |
| Virtual Private Server | T1583.003 | Des instances VPS réparties simulent un déploiement dispersé sous contrôle d'un seul opérateur. | Placement keyé sur la diversité réseau mesurée + quotas par-owner, et codage d'effacement empêchant que tout `k` réside chez un même opérateur. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Diversité de placement mesurée par le réseau | T1036, T1090.003, T1583.003 | — | SC-36 |
| Ledger SQLite par-owner + quotas/baux | T1583.003 | — | SC-6 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1583.003 | — | SC-36 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| Contrôles CTID (neo4j) | T1090.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-15 |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1090.003 | D3-EAL, D3-EDL, D3-ITF, D3-OTF | — |
