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

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Chiffrement client-side AES-256-GCM | T1213 | D3-MENCR | SC-28 |
| Encapsulation ML-KEM-768 (cap wrapping) | T1213 | D3-MENCR | SC-12 |
| Métadonnées d'effacement signées (stripe.Descriptor) | T1213 | D3-MAN | SI-7 |
| Adressage par hash de contenu | T1119 | D3-FH | SI-7 |
| Chunking taille fixe / normalisation des shards | T1119 | — | SC-4 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1589 | — | SC-5 |
| Contrôles CTID (neo4j) | T1213 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-16, AC-17, AC-21, AC-23, CA-7, CM-2, CM-3, CM-5, CM-6, CM-7, CM-8, IA-2, IA-4, IA-8, RA-5, SC-37, SI-4 |
| Contrôles CTID (neo4j) | T1119 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, SC-36, SI-4, SI-12 |
| Techniques D3FEND (neo4j) | T1213 | D3-EAL, D3-EDL, D3-ITF, D3-JFAPA, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-RAPA, D3-UAP, D3-UDTA | — |
| Techniques D3FEND (neo4j) | T1119 | D3-OSM | — |
