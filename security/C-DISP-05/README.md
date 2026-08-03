# C-DISP-05 — Saturation des vérifications

- **Cible** : Clients
- **Catégorie** : Disponibilité
- **Identifiant** : C-DISP-05

## Description
Un client soumet un volume de requêtes conçu pour saturer les mécanismes de vérification des nœuds.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | Le volume de requêtes vise à épuiser les mécanismes de vérification (hash, signatures) des nœuds. | Rate-limiter par-owner et appliquer les quotas du ledger pour plafonner le nombre de vérifications imposées. |
| Endpoint Denial of Service: Application or System Exploitation | T1499.004 | L'attaquant exploite le coût des vérifications pour maximiser la charge par requête. | Exiger une admission des écritures par preuve de travail argon2id (difficulté ≥ celle du nœud), rendant coûteux le fait de soumettre des vérifications en masse. |
