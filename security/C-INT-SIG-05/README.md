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
| Contrôles CTID (neo4j) | T1606 | — | AC-2, AC-5, AC-6, SC-17, SI-2 |
| Contrôles CTID (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-28, SC-43, SI-4 |
| Contrôles CTID (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1606 | D3-EAL, D3-EDL, D3-LFP, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1550.001 | D3-OSM | — |
