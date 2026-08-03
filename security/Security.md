
# Security Threat Model – Revika
## Objectif
Ce document recense les principaux scénarios d'attaque contre Revika afin d'alimenter les analyses de risque. Les mesures de défense associées sont détaillées, technique MITRE ATT&CK par technique, dans les fiches de l'arborescence [`security/`](./README.md).

Chaque scénario porte un identifiant unique. Convention : `<cible>-<catégorie>[-<sous-catégorie>]-<nn>`, où la cible est `N` (nœuds) ou `C` (clients). Ces identifiants sont stables : ne pas les réutiliser ni les renuméroter, ajouter les nouveaux scénarios à la suite.

## Actifs à protéger
- Données (shards)
- Métadonnées
- Droits d'accès
- Journal distribué
- Identités cryptographiques
- Disponibilité du réseau
- Localisation des nœuds
- Preuves de stockage

# Menaces visant les nœuds

## Confidentialité
### Données
- **N-CONF-01** — Lecture non autorisée des shards stockés.
- **N-CONF-02** — Analyse des accès.
- **N-CONF-03** — Corrélation des métadonnées.
- **N-CONF-04** — Observation des flux réseau.
- **N-CONF-05** — Inférence des relations entre utilisateurs.

## Intégrité
### Stockage
- **N-INT-STO-01** — Altération d'un shard.
- **N-INT-STO-02** — Fourniture d'un shard corrompu.
- **N-INT-STO-03** — Fourniture d'une ancienne version (rollback).
- **N-INT-STO-04** — Réorganisation locale des données.
### Métadonnées
- **N-INT-MET-01** — Falsification des métadonnées.
- **N-INT-MET-02** — Modification des timestamps.
- **N-INT-MET-03** — Réécriture de l'historique.
- **N-INT-MET-04** — Suppression d'événements locaux.
### Registre
- **N-INT-REG-01** — Double publication.
- **N-INT-REG-02** — Réécriture du registre.
- **N-INT-REG-03** — Omission d'événements.
- **N-INT-REG-04** — Création d'événements fictifs.
- **N-INT-REG-05** — Rejeu d'événements.
### Preuves
- **N-INT-PRE-01** — Fausses preuves de stockage.
- **N-INT-PRE-02** — Réutilisation d'anciennes preuves.
- **N-INT-PRE-03** — Mutualisation de preuves.
- **N-INT-PRE-04** — Fabrication de preuves sans données.
- **N-INT-PRE-05** — Falsification de preuves de disponibilité.
### Identité
- **N-INT-ID-01** — Usurpation d'identité.
- **N-INT-ID-02** — Duplication d'identité.
- **N-INT-ID-03** — Vol de clé privée.

## Disponibilité
- **N-DISP-01** — Suppression d'un shard.
- **N-DISP-02** — Refus de fournir un shard.
- **N-DISP-03** — Refus de répondre.
- **N-DISP-04** — Ralentissement volontaire.
- **N-DISP-05** — Partition réseau.
- **N-DISP-06** — Blocage du gossip.
- **N-DISP-07** — Saturation CPU, mémoire, disque ou bande passante.
- **N-DISP-08** — Refus de maintenance.
- **N-DISP-09** — Déconnexion stratégique.

## Contrôle d'accès
- **N-AC-01** — Ignorer une révocation.
- **N-AC-02** — Accorder un accès sans autorisation.
- **N-AC-03** — Servir des données après expiration.
- **N-AC-04** — Utiliser des permissions obsolètes.
- **N-AC-05** — Falsifier l'identité d'un demandeur.

## Menaces protocolaires
- **N-PROTO-01** — Injection de faux messages Gossip.
- **N-PROTO-02** — Attaque Eclipse.
- **N-PROTO-03** — Redirection vers de faux pairs.
- **N-PROTO-04** — Logiciel modifié.
- **N-PROTO-05** — Exploitation de vulnérabilités.
- **N-PROTO-06** — Désactivation de vérifications.

## Menaces économiques
- **N-ECO-01** — Déclarer une capacité fictive.
- **N-ECO-02** — Participer uniquement aux opérations rémunératrices.
- **N-ECO-03** — Quitter après récompense.
- **N-ECO-04** — Externaliser clandestinement le stockage.

## Menaces organisationnelles
### Sybil / collusion
- **N-ORG-SYB-01** — Création de faux nœuds.
- **N-ORG-SYB-02** — Collusion entre nœuds.
- **N-ORG-SYB-03** — Censure coordonnée.
- **N-ORG-SYB-04** — Contrôle d'une majorité régionale.
### Géolocalisation
- **N-ORG-GEO-01** — Fausser sa localisation.
- **N-ORG-GEO-02** — VPN/proxy.
- **N-ORG-GEO-03** — Concentration sur une même infrastructure.
- **N-ORG-GEO-04** — Répartition géographique fictive.

# Menaces visant les clients

## Confidentialité
- **C-CONF-01** — Déduire l'existence de données.
- **C-CONF-02** — Corrélation des métadonnées.
- **C-CONF-03** — Observation des temps de réponse.
- **C-CONF-04** — Collecte d'informations publiques.

## Intégrité
### Données
- **C-INT-DAT-01** — Envoi de données corrompues.
- **C-INT-DAT-02** — Modification non autorisée.
- **C-INT-DAT-03** — Versions incompatibles.
- **C-INT-DAT-04** — Suppression logique.
- **C-INT-DAT-05** — Injection de données malveillantes.
### Métadonnées
- **C-INT-MET-01** — Falsification.
- **C-INT-MET-02** — Modification des timestamps.
- **C-INT-MET-03** — Fausse origine.
- **C-INT-MET-04** — Manipulation des versions.
- **C-INT-MET-05** — Fausse liste de destinataires.
### Signatures
- **C-INT-SIG-01** — Double signature.
- **C-INT-SIG-02** — Signature d'un contenu différent.
- **C-INT-SIG-03** — Rejeu.
- **C-INT-SIG-04** — Signature volée.
- **C-INT-SIG-05** — Utilisation d'une clé compromise.
### Journaux
- **C-INT-JRN-01** — Empêcher un audit.
- **C-INT-JRN-02** — Événements contradictoires.
- **C-INT-JRN-03** — Bruit massif.
- **C-INT-JRN-04** — Réémission d'événements.

## Disponibilité
- **C-DISP-01** — Flood.
- **C-DISP-02** — Multiplication des connexions.
- **C-DISP-03** — Téléchargements interrompus.
- **C-DISP-04** — Demandes massives de reconstruction.
- **C-DISP-05** — Saturation des vérifications.

## Contrôle d'accès
- **C-AC-01** — Accès sans autorisation.
- **C-AC-02** — Réutilisation d'un droit expiré.
- **C-AC-03** — Jeton falsifié.
- **C-AC-04** — Escalade de privilèges.
- **C-AC-05** — Contournement d'une révocation.
- **C-AC-06** — Partage de droits.

## Menaces protocolaires
- **C-PROTO-01** — Non-respect du protocole.
- **C-PROTO-02** — Messages dans un ordre invalide.
- **C-PROTO-03** — Ancienne version du protocole.
- **C-PROTO-04** — Exploitation de comportements indéfinis.
- **C-PROTO-05** — Déclaration mensongère de capacités.

## Menaces économiques
- **C-ECO-01** — Création massive de données.
- **C-ECO-02** — Multiplication d'opérations.
- **C-ECO-03** — Création/suppression répétées.
- **C-ECO-04** — Tentative d'obtenir gratuitement des ressources.

## Collusion
- **C-COL-01** — Collusion entre clients.
- **C-COL-02** — Collusion avec des nœuds.
- **C-COL-03** — Partage de clés.
- **C-COL-04** — Création coordonnée de faux événements.
