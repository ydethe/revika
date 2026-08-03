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
| Contrôles CTID (neo4j) | T1119 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, SC-36, SI-4, SI-12 |
| Contrôles CTID (neo4j) | T1005 | — | AC-2, AC-3, AC-6, AC-16, AC-23, CM-12, CP-9, SA-8, SC-13, SC-28, SC-38, SI-3, SI-4 |
| Techniques D3FEND (neo4j) | T1119 | D3-OSM | — |
| Techniques D3FEND (neo4j) | T1005 | D3-EAL, D3-EDL, D3-FA, D3-JFAPA, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-RAPA, D3-UAP, D3-UDTA | — |
