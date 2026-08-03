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

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Rate-limiting par-owner (pubkey Ed25519) | T1499.003 | D3-ITF | SC-5 |
| Ledger SQLite par-owner + quotas/baux | T1499.003 | — | SC-6 |
| ConnectionGater / ResourceManager / ConnManager | T1498.001 | D3-NTF | SC-7 |
| Contrôles CTID (neo4j) | T1499.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| Contrôles CTID (neo4j) | T1498.001 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SI-15 |
| Techniques D3FEND (neo4j) | T1499.003 | D3-EAL, D3-EDL, D3-OSM, D3-OTF | — |
| Techniques D3FEND (neo4j) | T1498.001 | D3-EAL, D3-EDL, D3-ITF, D3-OTF | — |
