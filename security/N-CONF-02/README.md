# N-CONF-02 — Analyse des accès

- **Cible** : Nœuds
- **Catégorie** : Confidentialité › Données
- **Identifiant** : N-CONF-02

## Description
L'observation des motifs de lecture/écriture sur les shards (fréquence, séquence, taille) permet de déduire des informations sur les fichiers ou l'activité d'un utilisateur sans jamais déchiffrer les données.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Automated Collection | T1119 | Le nœud journalise et collecte automatiquement les accès pour en dériver des motifs de fréquence/séquence/taille. | Chunking de taille fixe + adressage par hash de contenu masquent la structure logique et la taille réelle des fichiers derrière des shards uniformes. |
| Data from Local System | T1005 | Exploitation des métadonnées d'accès locales (ordre et rythme des lectures/écritures) comme canal auxiliaire. | Codage d'effacement Reed-Solomon dispersant les accès sur au moins `k+m` nœuds indépendants : aucun nœud n'observe la séquence complète d'un fichier. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Chunking taille fixe / normalisation des shards | T1119 | — | SC-4 |
| Adressage par hash de contenu | T1119 | D3-FH | SI-7 |
| Placement réparti sur owners indépendants | T1005 | — | SC-36 |
