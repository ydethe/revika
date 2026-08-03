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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| ConnectionGater / ResourceManager / ConnManager | T1583.004 | D3-NTF | SC-7 |
| Diversité de placement mesurée par le réseau | T1583.004, T1036 | — | SC-36 |
| Placement réparti sur owners indépendants | T1036 | — | SC-36 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1036 | — | SC-36 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
