# N-ECO-03 — Quitter après récompense

- **Cible** : Nœuds
- **Catégorie** : Menaces économiques
- **Identifiant** : N-ECO-03

## Description
Un nœud collecte les récompenses puis quitte le réseau sans honorer ses engagements de conservation.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Destruction | T1485 | Analogue : le départ brutal du nœud rend indisponibles (« détruit ») les shards qu'il conservait. | Codage d'effacement Reed-Solomon (tout `k` reconstruit) + réparation obligatoire régénérant les shards perdus sur ciphertext déterministe reproduisant leur adresse de contenu. |
| Service Stop | T1489 | Le nœud cesse tout service après encaissement, interrompant l'accès aux données hébergées. | Baux (leases) à TTL et sondes de disponibilité détectant la sortie, déclenchant le re-placement vers d'autres owners avant expiration de la redondance. |
