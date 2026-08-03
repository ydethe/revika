# Modèle de menaces – arborescence `security/`


Cette arborescence éclate [`Security.md`](./Security.md) : un dossier par
scénario de menace, contenant un `README.md` qui le décrit. Le document source
reste la référence ; ces fiches permettent d'attacher notes de risque et
traçabilité menace par menace. Chaque fiche associe au scénario les techniques
MITRE ATT&CK mobilisées (avec leur identifiant) et une mesure de défense par
technique.

## Convention de nommage

`<cible>-<catégorie>[-<sous-catégorie>]-<nn>`, où la cible est `N` (nœuds) ou
`C` (clients). Les identifiants sont stables : ne pas les réutiliser ni les
renuméroter ; ajouter les nouveaux scénarios à la suite.

## Index des menaces

| ID | Cible | Catégorie | Intitulé |
| --- | --- | --- | --- |
| [N-CONF-01](./N-CONF-01/) | Nœuds | Confidentialité › Données | Lecture non autorisée des shards stockés |
| [N-CONF-02](./N-CONF-02/) | Nœuds | Confidentialité › Données | Analyse des accès |
| [N-CONF-03](./N-CONF-03/) | Nœuds | Confidentialité › Données | Corrélation des métadonnées |
| [N-CONF-04](./N-CONF-04/) | Nœuds | Confidentialité › Données | Observation des flux réseau |
| [N-CONF-05](./N-CONF-05/) | Nœuds | Confidentialité › Données | Inférence des relations entre utilisateurs |
| [N-INT-STO-01](./N-INT-STO-01/) | Nœuds | Intégrité › Stockage | Altération d'un shard |
| [N-INT-STO-02](./N-INT-STO-02/) | Nœuds | Intégrité › Stockage | Fourniture d'un shard corrompu |
| [N-INT-STO-03](./N-INT-STO-03/) | Nœuds | Intégrité › Stockage | Fourniture d'une ancienne version (rollback) |
| [N-INT-STO-04](./N-INT-STO-04/) | Nœuds | Intégrité › Stockage | Réorganisation locale des données |
| [N-INT-MET-01](./N-INT-MET-01/) | Nœuds | Intégrité › Métadonnées | Falsification des métadonnées |
| [N-INT-MET-02](./N-INT-MET-02/) | Nœuds | Intégrité › Métadonnées | Modification des timestamps |
| [N-INT-MET-03](./N-INT-MET-03/) | Nœuds | Intégrité › Métadonnées | Réécriture de l'historique |
| [N-INT-MET-04](./N-INT-MET-04/) | Nœuds | Intégrité › Métadonnées | Suppression d'événements locaux |
| [N-INT-REG-01](./N-INT-REG-01/) | Nœuds | Intégrité › Registre | Double publication |
| [N-INT-REG-02](./N-INT-REG-02/) | Nœuds | Intégrité › Registre | Réécriture du registre |
| [N-INT-REG-03](./N-INT-REG-03/) | Nœuds | Intégrité › Registre | Omission d'événements |
| [N-INT-REG-04](./N-INT-REG-04/) | Nœuds | Intégrité › Registre | Création d'événements fictifs |
| [N-INT-REG-05](./N-INT-REG-05/) | Nœuds | Intégrité › Registre | Rejeu d'événements |
| [N-INT-PRE-01](./N-INT-PRE-01/) | Nœuds | Intégrité › Preuves | Fausses preuves de stockage |
| [N-INT-PRE-02](./N-INT-PRE-02/) | Nœuds | Intégrité › Preuves | Réutilisation d'anciennes preuves |
| [N-INT-PRE-03](./N-INT-PRE-03/) | Nœuds | Intégrité › Preuves | Mutualisation de preuves |
| [N-INT-PRE-04](./N-INT-PRE-04/) | Nœuds | Intégrité › Preuves | Fabrication de preuves sans données |
| [N-INT-PRE-05](./N-INT-PRE-05/) | Nœuds | Intégrité › Preuves | Falsification de preuves de disponibilité |
| [N-INT-ID-01](./N-INT-ID-01/) | Nœuds | Intégrité › Identité | Usurpation d'identité |
| [N-INT-ID-02](./N-INT-ID-02/) | Nœuds | Intégrité › Identité | Duplication d'identité |
| [N-INT-ID-03](./N-INT-ID-03/) | Nœuds | Intégrité › Identité | Vol de clé privée |
| [N-DISP-01](./N-DISP-01/) | Nœuds | Disponibilité | Suppression d'un shard |
| [N-DISP-02](./N-DISP-02/) | Nœuds | Disponibilité | Refus de fournir un shard |
| [N-DISP-03](./N-DISP-03/) | Nœuds | Disponibilité | Refus de répondre |
| [N-DISP-04](./N-DISP-04/) | Nœuds | Disponibilité | Ralentissement volontaire |
| [N-DISP-05](./N-DISP-05/) | Nœuds | Disponibilité | Partition réseau |
| [N-DISP-06](./N-DISP-06/) | Nœuds | Disponibilité | Blocage du gossip |
| [N-DISP-07](./N-DISP-07/) | Nœuds | Disponibilité | Saturation CPU, mémoire, disque ou bande passante |
| [N-DISP-08](./N-DISP-08/) | Nœuds | Disponibilité | Refus de maintenance |
| [N-DISP-09](./N-DISP-09/) | Nœuds | Disponibilité | Déconnexion stratégique |
| [N-AC-01](./N-AC-01/) | Nœuds | Contrôle d'accès | Ignorer une révocation |
| [N-AC-02](./N-AC-02/) | Nœuds | Contrôle d'accès | Accorder un accès sans autorisation |
| [N-AC-03](./N-AC-03/) | Nœuds | Contrôle d'accès | Servir des données après expiration |
| [N-AC-04](./N-AC-04/) | Nœuds | Contrôle d'accès | Utiliser des permissions obsolètes |
| [N-AC-05](./N-AC-05/) | Nœuds | Contrôle d'accès | Falsifier l'identité d'un demandeur |
| [N-PROTO-01](./N-PROTO-01/) | Nœuds | Menaces protocolaires | Injection de faux messages Gossip |
| [N-PROTO-02](./N-PROTO-02/) | Nœuds | Menaces protocolaires | Attaque Eclipse |
| [N-PROTO-03](./N-PROTO-03/) | Nœuds | Menaces protocolaires | Redirection vers de faux pairs |
| [N-PROTO-04](./N-PROTO-04/) | Nœuds | Menaces protocolaires | Logiciel modifié |
| [N-PROTO-05](./N-PROTO-05/) | Nœuds | Menaces protocolaires | Exploitation de vulnérabilités |
| [N-PROTO-06](./N-PROTO-06/) | Nœuds | Menaces protocolaires | Désactivation de vérifications |
| [N-ECO-01](./N-ECO-01/) | Nœuds | Menaces économiques | Déclarer une capacité fictive |
| [N-ECO-02](./N-ECO-02/) | Nœuds | Menaces économiques | Participer uniquement aux opérations rémunératrices |
| [N-ECO-03](./N-ECO-03/) | Nœuds | Menaces économiques | Quitter après récompense |
| [N-ECO-04](./N-ECO-04/) | Nœuds | Menaces économiques | Externaliser clandestinement le stockage |
| [N-ORG-SYB-01](./N-ORG-SYB-01/) | Nœuds | Menaces organisationnelles › Sybil / collusion | Création de faux nœuds |
| [N-ORG-SYB-02](./N-ORG-SYB-02/) | Nœuds | Menaces organisationnelles › Sybil / collusion | Collusion entre nœuds |
| [N-ORG-SYB-03](./N-ORG-SYB-03/) | Nœuds | Menaces organisationnelles › Sybil / collusion | Censure coordonnée |
| [N-ORG-SYB-04](./N-ORG-SYB-04/) | Nœuds | Menaces organisationnelles › Sybil / collusion | Contrôle d'une majorité régionale |
| [N-ORG-GEO-01](./N-ORG-GEO-01/) | Nœuds | Menaces organisationnelles › Géolocalisation | Fausser sa localisation |
| [N-ORG-GEO-02](./N-ORG-GEO-02/) | Nœuds | Menaces organisationnelles › Géolocalisation | VPN/proxy |
| [N-ORG-GEO-03](./N-ORG-GEO-03/) | Nœuds | Menaces organisationnelles › Géolocalisation | Concentration sur une même infrastructure |
| [N-ORG-GEO-04](./N-ORG-GEO-04/) | Nœuds | Menaces organisationnelles › Géolocalisation | Répartition géographique fictive |
| [C-CONF-01](./C-CONF-01/) | Clients | Confidentialité | Déduire l'existence de données |
| [C-CONF-02](./C-CONF-02/) | Clients | Confidentialité | Corrélation des métadonnées |
| [C-CONF-03](./C-CONF-03/) | Clients | Confidentialité | Observation des temps de réponse |
| [C-CONF-04](./C-CONF-04/) | Clients | Confidentialité | Collecte d'informations publiques |
| [C-INT-DAT-01](./C-INT-DAT-01/) | Clients | Intégrité › Données | Envoi de données corrompues |
| [C-INT-DAT-02](./C-INT-DAT-02/) | Clients | Intégrité › Données | Modification non autorisée |
| [C-INT-DAT-03](./C-INT-DAT-03/) | Clients | Intégrité › Données | Versions incompatibles |
| [C-INT-DAT-04](./C-INT-DAT-04/) | Clients | Intégrité › Données | Suppression logique |
| [C-INT-DAT-05](./C-INT-DAT-05/) | Clients | Intégrité › Données | Injection de données malveillantes |
| [C-INT-MET-01](./C-INT-MET-01/) | Clients | Intégrité › Métadonnées | Falsification |
| [C-INT-MET-02](./C-INT-MET-02/) | Clients | Intégrité › Métadonnées | Modification des timestamps |
| [C-INT-MET-03](./C-INT-MET-03/) | Clients | Intégrité › Métadonnées | Fausse origine |
| [C-INT-MET-04](./C-INT-MET-04/) | Clients | Intégrité › Métadonnées | Manipulation des versions |
| [C-INT-MET-05](./C-INT-MET-05/) | Clients | Intégrité › Métadonnées | Fausse liste de destinataires |
| [C-INT-SIG-01](./C-INT-SIG-01/) | Clients | Intégrité › Signatures | Double signature |
| [C-INT-SIG-02](./C-INT-SIG-02/) | Clients | Intégrité › Signatures | Signature d'un contenu différent |
| [C-INT-SIG-03](./C-INT-SIG-03/) | Clients | Intégrité › Signatures | Rejeu |
| [C-INT-SIG-04](./C-INT-SIG-04/) | Clients | Intégrité › Signatures | Signature volée |
| [C-INT-SIG-05](./C-INT-SIG-05/) | Clients | Intégrité › Signatures | Utilisation d'une clé compromise |
| [C-INT-JRN-01](./C-INT-JRN-01/) | Clients | Intégrité › Journaux | Empêcher un audit |
| [C-INT-JRN-02](./C-INT-JRN-02/) | Clients | Intégrité › Journaux | Événements contradictoires |
| [C-INT-JRN-03](./C-INT-JRN-03/) | Clients | Intégrité › Journaux | Bruit massif |
| [C-INT-JRN-04](./C-INT-JRN-04/) | Clients | Intégrité › Journaux | Réémission d'événements |
| [C-DISP-01](./C-DISP-01/) | Clients | Disponibilité | Flood |
| [C-DISP-02](./C-DISP-02/) | Clients | Disponibilité | Multiplication des connexions |
| [C-DISP-03](./C-DISP-03/) | Clients | Disponibilité | Téléchargements interrompus |
| [C-DISP-04](./C-DISP-04/) | Clients | Disponibilité | Demandes massives de reconstruction |
| [C-DISP-05](./C-DISP-05/) | Clients | Disponibilité | Saturation des vérifications |
| [C-AC-01](./C-AC-01/) | Clients | Contrôle d'accès | Accès sans autorisation |
| [C-AC-02](./C-AC-02/) | Clients | Contrôle d'accès | Réutilisation d'un droit expiré |
| [C-AC-03](./C-AC-03/) | Clients | Contrôle d'accès | Jeton falsifié |
| [C-AC-04](./C-AC-04/) | Clients | Contrôle d'accès | Escalade de privilèges |
| [C-AC-05](./C-AC-05/) | Clients | Contrôle d'accès | Contournement d'une révocation |
| [C-AC-06](./C-AC-06/) | Clients | Contrôle d'accès | Partage de droits |
| [C-PROTO-01](./C-PROTO-01/) | Clients | Menaces protocolaires | Non-respect du protocole |
| [C-PROTO-02](./C-PROTO-02/) | Clients | Menaces protocolaires | Messages dans un ordre invalide |
| [C-PROTO-03](./C-PROTO-03/) | Clients | Menaces protocolaires | Ancienne version du protocole |
| [C-PROTO-04](./C-PROTO-04/) | Clients | Menaces protocolaires | Exploitation de comportements indéfinis |
| [C-PROTO-05](./C-PROTO-05/) | Clients | Menaces protocolaires | Déclaration mensongère de capacités |
| [C-ECO-01](./C-ECO-01/) | Clients | Menaces économiques | Création massive de données |
| [C-ECO-02](./C-ECO-02/) | Clients | Menaces économiques | Multiplication d'opérations |
| [C-ECO-03](./C-ECO-03/) | Clients | Menaces économiques | Création/suppression répétées |
| [C-ECO-04](./C-ECO-04/) | Clients | Menaces économiques | Tentative d'obtenir gratuitement des ressources |
| [C-COL-01](./C-COL-01/) | Clients | Collusion | Collusion entre clients |
| [C-COL-02](./C-COL-02/) | Clients | Collusion | Collusion avec des nœuds |
| [C-COL-03](./C-COL-03/) | Clients | Collusion | Partage de clés |
| [C-COL-04](./C-COL-04/) | Clients | Collusion | Création coordonnée de faux événements |
