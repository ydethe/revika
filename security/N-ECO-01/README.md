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

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Sondes + défis de possession | — | SI-7 |
| Ledger SQLite par-owner + quotas/baux | — | SC-6 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | — | SC-5 |
