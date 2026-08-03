# N-INT-ID-02 — Duplication d'identité

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Identité
- **Identifiant** : N-INT-ID-02

## Description
Une même identité cryptographique de nœud est instanciée sur plusieurs machines pour brouiller la comptabilité et le placement.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Valid Accounts | T1078 | La même identité de nœud valide est réutilisée sur plusieurs machines pour fausser comptabilité et placement. | Rate-limiting et quotas du ledger keyés sur la pubkey Ed25519 : une identité unique reste plafonnée quel que soit le nombre de machines. |
| Botnet | T1584.005 | Analogue : plusieurs hôtes opèrent sous une identité unique, formant un ensemble contrôlé masquant sa réelle distribution. | Placement fondé sur la diversité de shards vérifiés par hash et probes de possession, empêchant une identité dupliquée de simuler une redondance distribuée. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Rate-limiting par-owner (pubkey Ed25519) | T1078 | D3-ITF | SC-5 |
| Ledger SQLite par-owner + quotas/baux | T1078 | — | SC-6 |
| Diversité de placement mesurée par le réseau | T1584.005 | — | SC-36 |
| Sondes + défis de possession | T1584.005 | — | SI-7 |
| Contrôles CTID (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-7, SC-28, SC-43, SI-4 |
| Techniques D3FEND (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
