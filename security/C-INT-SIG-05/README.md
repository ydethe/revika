# C-INT-SIG-05 — Utilisation d'une clé compromise

- **Cible** : Clients
- **Catégorie** : Intégrité › Signatures
- **Identifiant** : C-INT-SIG-05

## Description
Une clé de signature compromise continue d'être acceptée, permettant de forger des autorisations.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Valid Accounts | T1078 | La clé d'owner compromise reste un identifiant valide et donc encore accepté par les nœuds. | Maintenir une liste de révocation et permettre le bannissement par pubkey Ed25519 (ConnectionGater / ledger), pour cesser d'honorer une clé compromise. |
| Forge Web Credentials | T1606 | L'attaquant forge des autorisations (capacités/jetons) au nom de l'owner grâce à la clé compromise. | Lier chaque autorisation à des capacités signées à TTL court révocables, de sorte qu'une forge ne survive pas à la révocation de la clé. |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Les jetons signés par la clé compromise continuent d'ouvrir l'accès. | Invalider les baux/jetons de l'identité compromise dans le ledger et exiger une nouvelle identité PoW pour ré-admettre des écritures. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Capacités TTL court + révocation | T1606 | — | AC-3 |
| ConnectionGater / ResourceManager / ConnManager | T1078 | D3-NTF | SC-7 |
| Ledger SQLite par-owner + quotas/baux | T1078, T1550.001 | — | SC-6 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1550.001 | — | SC-5 |
