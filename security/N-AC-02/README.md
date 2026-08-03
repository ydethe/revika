# N-AC-02 — Accorder un accès sans autorisation

- **Cible** : Nœuds
- **Catégorie** : Contrôle d'accès
- **Identifiant** : N-AC-02

## Description
Un nœud sert un shard à un demandeur qui ne présente aucune autorisation valide.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data from Cloud Storage | T1530 | L'attaquant récupère un shard stocké dans un nœud sans présenter de capacité valide, en analogue P2P de l'accès direct à un stockage objet. | Admission des lectures conditionnée à la présentation d'une capacité/jeton signé vérifié contre le ledger, refus par défaut en l'absence d'autorisation. |
| Valid Accounts | T1078 | Le demandeur obtient un accès qu'il ne devrait pas avoir, faute de contrôle d'autorisation côté nœud. | Authentification des demandeurs sur pubkey Ed25519 auto-certifiante et vérification systématique du droit d'accès avant tout service de ciphertext. |
