# C-AC-04 — Escalade de privilèges

- **Cible** : Clients
- **Catégorie** : Contrôle d'accès
- **Identifiant** : C-AC-04

## Description
Un client transforme un accès limité en un accès plus étendu que celui qui lui a été accordé.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Abuse Elevation Control Mechanism | T1548 | Le client détourne le mécanisme d'octroi de capacités pour étendre son périmètre au-delà de l'accordé. | Capacités liées cryptographiquement à un périmètre précis (read-capability = localisation manifest + clé encapsulée ML-KEM), non extensibles sans une nouvelle capacité signée. |
| Exploitation for Privilege Escalation | T1068 | Le client exploite une faille du contrôle d'accès pour obtenir des droits supérieurs. | Contrôle d'accès porté par la cryptographie plutôt que par des rôles serveur, et propriété/quota arbitrés par le ledger SQLite par-owner. |
