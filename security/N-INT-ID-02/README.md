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

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Rate-limiting par-owner (pubkey Ed25519) | D3-ITF | SC-5 |
| Ledger SQLite par-owner + quotas/baux | — | SC-6 |
| Diversité de placement mesurée par le réseau | — | SC-36 |
| Sondes + défis de possession | — | SI-7 |
