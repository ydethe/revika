# C-INT-MET-05 — Fausse liste de destinataires

- **Cible** : Clients
- **Catégorie** : Intégrité › Métadonnées
- **Identifiant** : C-INT-MET-05

## Description
La liste des destinataires d'un partage est falsifiée, ajoutant ou retirant des accès indûment.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | La liste des destinataires d'un partage est modifiée pour ajouter ou retirer des accès indûment. | Capacités encapsulées individuellement en ML-KEM-768 par destinataire et liste de partage signée Ed25519, avec révocation gérée par le propriétaire. |
| Impersonation | T1656 | Un attaquant s'ajoute comme destinataire légitime pour obtenir un accès non consenti. | Encapsulation de la capacité à la pubkey du seul destinataire visé, un accès non prévu ne pouvant déchiffrer la clé. |
