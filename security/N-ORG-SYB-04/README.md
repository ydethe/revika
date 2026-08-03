# N-ORG-SYB-04 — Contrôle d'une majorité régionale

- **Cible** : Nœuds
- **Catégorie** : Menaces organisationnelles › Sybil / collusion
- **Identifiant** : N-ORG-SYB-04

## Description
Un acteur contrôle assez de nœuds dans une région pour dominer les décisions ou le stockage local.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Establish Accounts | T1585 | L'acteur amasse assez d'identités de nœuds dans une région pour y dominer placement et stockage. | Preuve de travail sur l'identité (argon2id) + quotas par-owner : concentrer un poids régional coûte du CPU et reste plafonné par le ledger. |
| Botnet | T1583.005 | Le parc régional concentré fonctionne comme un botnet dominant les décisions locales. | Politique de placement imposant une diversité inter-owner et inter-région, contrôlée par sous-réseau/AS observé via le `ConnectionGater`. |
| Trusted Relationship | T1199 | Les nœuds régionaux coordonnés forment une relation de confiance abusée pour capter le stockage local. | Codage d'effacement dispersant les shards hors d'une seule région : aucun `k` complet ne peut résider dans la zone dominée. |
