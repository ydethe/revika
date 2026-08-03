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
