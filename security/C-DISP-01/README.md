# C-DISP-01 — Flood

- **Cible** : Clients
- **Catégorie** : Disponibilité
- **Identifiant** : C-DISP-01

## Description
Un client malveillant inonde le réseau de requêtes pour dégrader la disponibilité pour les autres.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | Le déluge de requêtes applicatives épuise les nœuds et dégrade le service pour les autres. | Appliquer un rate-limiting par-pair / par-owner (clé sur la pubkey Ed25519) et les quotas du ledger pour plafonner le débit de requêtes. |
| Network Denial of Service: Direct Network Flood | T1498.001 | L'inondation directe du réseau sature la bande passante et la capacité de traitement des nœuds. | Wirer les défenses de `internal/net/defense.go` (`ResourceManager` + `ConnManager`) et bloquer les pairs/sous-réseaux abusifs via `ConnectionGater`. |
