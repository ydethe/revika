# N-INT-MET-01 — Falsification des métadonnées

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Métadonnées
- **Identifiant** : N-INT-MET-01

## Description
Le nœud modifie les métadonnées associées aux shards (propriétaire, bail, quota, stripe) pour tromper les autres participants.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Le nœud falsifie dans son ledger SQLite les métadonnées de propriété, bail, quota ou stripe rattachées aux shards. | Métadonnées d'effacement signées (`stripe.Descriptor`, grant de réparation signé) : une métadonnée falsifiée invalide la signature Ed25519 et est rejetée. |
| Masquerading | T1036 | En réécrivant le propriétaire d'un shard, le nœud fait passer une donnée pour appartenant à un autre owner que le titulaire réel. | Propriété liée à la pubkey Ed25519 auto-certifiante de l'owner et capacités signées encapsulées ML-KEM-768 : l'appartenance n'est pas réattribuable localement par le nœud. |
