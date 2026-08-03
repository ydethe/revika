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
| Contrôles CTID (neo4j) | T1552 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-5, CM-6, CM-7, IA-2, IA-3, IA-4, IA-5, RA-5, SA-11, SA-15, SC-4, SC-7, SC-28, SI-2, SI-4, SI-7, SI-12, SI-15 |
| Contrôles CTID (neo4j) | T1649 | — | IA-2, IA-5 |
| Contrôles CTID (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-28, SC-43, SI-4 |
| Techniques D3FEND (neo4j) | T1552 | D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
