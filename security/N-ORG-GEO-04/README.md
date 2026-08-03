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

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Diversité de placement mesurée par le réseau | — | SC-36 |
| Ledger SQLite par-owner + quotas/baux | — | SC-6 |
| Codage Reed-Solomon k=4/m=2 + réparation | — | SC-36 |
