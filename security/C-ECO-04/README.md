# C-ECO-04 — Tentative d'obtenir gratuitement des ressources

- **Cible** : Clients
- **Catégorie** : Menaces économiques
- **Identifiant** : C-ECO-04

## Description
Un client cherche à consommer stockage et bande passante sans s'acquitter de la contrepartie attendue.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Resource Hijacking | T1496 | Le client consomme stockage et bande passante sans fournir la contrepartie attendue. | Admission des écritures sous preuve de travail (coût CPU par identité), quotas par-owner du ledger et rate-limiting/`ConnManager` bornant la bande passante par pair. |
