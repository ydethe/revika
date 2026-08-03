# N-INT-ID-03 — Vol de clé privée

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Identité
- **Identifiant** : N-INT-ID-03

## Description
La clé privée d'identité d'un nœud est dérobée, permettant à l'attaquant d'agir sous cette identité.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Unsecured Credentials | T1552 | La clé privée d'identité du nœud est dérobée là où elle est stockée en clair sur l'hôte. | Stockage restreint des clés sous `.revika/keys` avec permissions strictes ; isolation crypto stdlib et clés jamais transmises hors machine. |
| Steal or Forge Authentication Certificates | T1649 | L'attaquant obtient le matériel cryptographique d'identité pour signer comme le nœud légitime. | Rotation/révocation de l'identité et rebroyage PoW (argon2id) d'une nouvelle identité auto-certifiante, invalidant l'usage de la clé volée. |
| Valid Accounts | T1078 | Muni de la clé volée, l'attaquant agit sous l'identité authentique du nœud sur le réseau. | Baux et quotas du ledger à TTL par owner + blocklist du `ConnectionGater`, limitant l'abus et permettant d'exclure l'identité compromise. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Isolation des clés côté client (.revika/keys) | T1552 | — | SC-12 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1649 | — | SC-5 |
| Ledger SQLite par-owner + quotas/baux | T1078 | — | SC-6 |
| ConnectionGater / ResourceManager / ConnManager | T1078 | D3-NTF | SC-7 |
