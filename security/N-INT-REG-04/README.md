# N-INT-REG-04 — Création d'événements fictifs

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Registre
- **Identifiant** : N-INT-REG-04

## Description
Un nœud inscrit dans le registre des événements qui n'ont jamais eu lieu (faux stockage, faux transfert).

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Stored Data Manipulation | T1565.001 | Le nœud fabrique des entrées de registre (faux stockage, faux transfert) sans réalité sous-jacente. | Chaque événement doit référencer un shard vérifiable par hash de contenu et une capacité/grant signé, sinon il est rejeté. |
| Masquerading | T1036 | Les faux événements font passer une activité inexistante pour une opération légitime de stockage ou de transfert. | Corroboration croisée : un événement de stockage n'est admis qu'après preuve de détention vérifiable par le pair de contrôle. |
