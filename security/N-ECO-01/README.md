# N-ECO-01 — Déclarer une capacité fictive

- **Cible** : Nœuds
- **Catégorie** : Menaces économiques
- **Identifiant** : N-ECO-01

## Description
Un nœud annonce une capacité de stockage supérieure à sa capacité réelle pour attirer des placements.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Masquerading | T1036 | Le nœud présente un attribut de capacité falsifié pour paraître mieux doté qu'il ne l'est et capter des placements. | Ne pas se fier aux annonces : valider la détention réelle par sondes de disponibilité (`internal/repair`) recomputant le hash de contenu des shards, et plafonner via le quota par-owner du ledger SQLite. |
| Social Engineering: Impersonation | T1684.001 | Analogue P2P : le nœud se fait passer pour un pair honnête et bien provisionné afin d'obtenir la confiance de la politique de placement. | Placement keyé sur la pubkey Ed25519 auto-certifiée et vérification périodique par challenge de possession (adressage par hash) plutôt que sur les déclarations du pair. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Sondes + défis de possession | T1036, T1684.001 | — | SI-7 |
| Ledger SQLite par-owner + quotas/baux | T1036 | — | SC-6 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1684.001 | — | SC-5 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
