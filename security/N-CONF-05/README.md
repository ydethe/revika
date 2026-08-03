# N-CONF-05 — Inférence des relations entre utilisateurs

- **Cible** : Nœuds
- **Catégorie** : Confidentialité › Données
- **Identifiant** : N-CONF-05

## Description
En corrélant les propriétaires, les destinataires de partages et les schémas de placement, un observateur reconstitue le graphe des relations entre utilisateurs.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Gather Victim Identity Information | T1589 | Corrélation des propriétaires et des destinataires de partages pour identifier des utilisateurs et leurs liens. | Capacités read encapsulées en ML-KEM-768 à la pubkey du destinataire : aucun destinataire en clair n'apparaît côté nœud. |
| Gather Victim Org Information | T1591 | Reconstitution du graphe de relations à partir des schémas de placement observés. | Partages et placements médiés par capacités signées ; le nœud ne manipule que des pubkeys Ed25519 opaques sans sémantique de relation. |
| Automated Collection | T1119 | Collecte systématique des propriétaires/destinataires/placements pour bâtir le graphe social. | Rate-limiting par-owner et identités auto-certifiées par preuve de travail (argon2id, `internal/cap/pow.go`) freinant l'accumulation et l'énumération. |
