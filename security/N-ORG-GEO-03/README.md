# N-ORG-GEO-03 — Concentration sur une même infrastructure

- **Cible** : Nœuds
- **Catégorie** : Menaces organisationnelles › Géolocalisation
- **Identifiant** : N-ORG-GEO-03

## Description
Des nœuds apparemment distincts sont hébergés sur une même infrastructure, annulant la redondance géographique.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Server | T1583.004 | Plusieurs identités de nœuds sont acquises et exécutées sur un même serveur/hébergeur, annulant la redondance géographique. | Détection de colocation par sous-réseau/AS observé via le `ConnectionGater` et corrélation de latence, pour éviter de placer plusieurs shards `k` sur une même infra. |
| Masquerading | T1036 | Les nœuds colocalisés se présentent comme indépendants pour tromper la politique de répartition. | Placement imposant des owners distincts (pubkey Ed25519) et une diversité réseau mesurée, complété par la tolérance du codage d'effacement. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| ConnectionGater / ResourceManager / ConnManager | D3-NTF | SC-7 |
| Diversité de placement mesurée par le réseau | — | SC-36 |
| Placement réparti sur owners indépendants | — | SC-36 |
| Codage Reed-Solomon k=4/m=2 + réparation | — | SC-36 |
