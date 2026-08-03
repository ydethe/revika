# C-CONF-02 — Corrélation des métadonnées

- **Cible** : Clients
- **Catégorie** : Confidentialité
- **Identifiant** : C-CONF-02

## Description
Le recoupement de métadonnées côté client (manifestes, identifiants, tailles) permet de relier des données ou des utilisateurs.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data from Information Repositories | T1213 | L'attaquant exploite les manifestes et index de stripe comme dépôt d'informations pour corréler données et utilisateurs. | Chiffrement client-side des manifestes et encapsulation des capacités en ML-KEM-768, les métadonnées d'effacement non confidentielles (`stripe.Descriptor`) étant minimisées. |
| Automated Collection | T1119 | Le recoupement automatisé des identifiants et tailles de shards permet de lier des jeux de données entre eux. | Adressage par hash de contenu et shards de taille normalisée par le chunking, réduisant les corrélations exploitables. |
| Gather Victim Identity Information | T1589 | Les pubkeys Ed25519/ML-KEM associées aux manifestes servent à relier des utilisateurs à leurs données. | Identités auto-certifiées libp2p sans lien avec l'identité réelle, capacités encapsulées par destinataire sans exposer la liste des accès. |
