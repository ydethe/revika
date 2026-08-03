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

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Rate-limiting par-owner (pubkey Ed25519) | T1499.003 | D3-ITF | SC-5 |
| Ledger SQLite par-owner + quotas/baux | T1499.003 | — | SC-6 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1499.004 | — | SC-5 |
| Contrôles CTID (neo4j) | T1499.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| Contrôles CTID (neo4j) | T1499.004 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-4, SI-15 |
| Techniques D3FEND (neo4j) | T1499.003 | D3-EAL, D3-EDL, D3-OSM, D3-OTF | — |
| Techniques D3FEND (neo4j) | T1499.004 | D3-EAL, D3-EDL, D3-ITF, D3-OSM, D3-OTF | — |
