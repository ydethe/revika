
# Security Threat Model – Revika
## Objectif
Ce document recense les principaux scénarios d'attaque contre Revika afin d'alimenter les analyses de risque. Il ne contient volontairement aucune mesure de défense.

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
- Lecture non autorisée des shards stockés.
- Analyse des accès.
- Corrélation des métadonnées.
- Observation des flux réseau.
- Inférence des relations entre utilisateurs.

## Intégrité
### Stockage
- Altération d'un shard.
- Fourniture d'un shard corrompu.
- Fourniture d'une ancienne version (rollback).
- Réorganisation locale des données.
### Métadonnées
- Falsification des métadonnées.
- Modification des timestamps.
- Réécriture de l'historique.
- Suppression d'événements locaux.
### Registre
- Double publication.
- Réécriture du registre.
- Omission d'événements.
- Création d'événements fictifs.
- Rejeu d'événements.
### Preuves
- Fausses preuves de stockage.
- Réutilisation d'anciennes preuves.
- Mutualisation de preuves.
- Fabrication de preuves sans données.
- Falsification de preuves de disponibilité.
### Identité
- Usurpation d'identité.
- Duplication d'identité.
- Vol de clé privée.

## Disponibilité
- Suppression d'un shard.
- Refus de fournir un shard.
- Refus de répondre.
- Ralentissement volontaire.
- Partition réseau.
- Blocage du gossip.
- Saturation CPU, mémoire, disque ou bande passante.
- Refus de maintenance.
- Déconnexion stratégique.

## Contrôle d'accès
- Ignorer une révocation.
- Accorder un accès sans autorisation.
- Servir des données après expiration.
- Utiliser des permissions obsolètes.
- Falsifier l'identité d'un demandeur.

## Menaces protocolaires
- Injection de faux messages Gossip.
- Attaque Eclipse.
- Redirection vers de faux pairs.
- Logiciel modifié.
- Exploitation de vulnérabilités.
- Désactivation de vérifications.

## Menaces économiques
- Déclarer une capacité fictive.
- Participer uniquement aux opérations rémunératrices.
- Quitter après récompense.
- Externaliser clandestinement le stockage.

## Menaces organisationnelles
### Sybil / collusion
- Création de faux nœuds.
- Collusion entre nœuds.
- Censure coordonnée.
- Contrôle d'une majorité régionale.
### Géolocalisation
- Fausser sa localisation.
- VPN/proxy.
- Concentration sur une même infrastructure.
- Répartition géographique fictive.

# Menaces visant les clients

## Confidentialité
- Déduire l'existence de données.
- Corrélation des métadonnées.
- Observation des temps de réponse.
- Collecte d'informations publiques.

## Intégrité
### Données
- Envoi de données corrompues.
- Modification non autorisée.
- Versions incompatibles.
- Suppression logique.
- Injection de données malveillantes.
### Métadonnées
- Falsification.
- Modification des timestamps.
- Fausse origine.
- Manipulation des versions.
- Fausse liste de destinataires.
### Signatures
- Double signature.
- Signature d'un contenu différent.
- Rejeu.
- Signature volée.
- Utilisation d'une clé compromise.
### Journaux
- Empêcher un audit.
- Événements contradictoires.
- Bruit massif.
- Réémission d'événements.

## Disponibilité
- Flood.
- Multiplication des connexions.
- Téléchargements interrompus.
- Demandes massives de reconstruction.
- Saturation des vérifications.

## Contrôle d'accès
- Accès sans autorisation.
- Réutilisation d'un droit expiré.
- Jeton falsifié.
- Escalade de privilèges.
- Contournement d'une révocation.
- Partage de droits.

## Menaces protocolaires
- Non-respect du protocole.
- Messages dans un ordre invalide.
- Ancienne version du protocole.
- Exploitation de comportements indéfinis.
- Déclaration mensongère de capacités.

## Menaces économiques
- Création massive de données.
- Multiplication d'opérations.
- Création/suppression répétées.
- Tentative d'obtenir gratuitement des ressources.

## Collusion
- Collusion entre clients.
- Collusion avec des nœuds.
- Partage de clés.
- Création coordonnée de faux événements.
