# N-INT-ID-01 — Usurpation d'identité

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Identité
- **Identifiant** : N-INT-ID-01

## Description
Un nœud se fait passer pour un autre nœud (ou pour un propriétaire) afin de bénéficier de ses droits ou de sa réputation.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Impersonation | T1656 | Le nœud prétend être un autre nœud ou un propriétaire pour hériter de ses droits ou de sa réputation. | Identités libp2p auto-certifiées et signatures Ed25519 : tout message/écriture est authentifié par la pubkey réelle, non usurpable sans la clé privée. |
| Valid Accounts | T1078 | Analogue : l'attaquant exploite l'identité d'un pair légitime pour accéder à ses droits sur le réseau. | Transport libp2p chiffré/authentifié et capacités signées liées à la pubkey du titulaire, avec quotas et baux du ledger indexés sur l'owner Ed25519. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Signatures / capacités Ed25519 | T1656, T1078 | D3-MAN | AU-10 |
| Transport libp2p chiffré / authentifié | T1078 | D3-MENCR | SC-8 |
| Ledger SQLite par-owner + quotas/baux | T1078 | — | SC-6 |
| Contrôles CTID (neo4j) | T1078 | — | AC-2, AC-3, AC-5, AC-6, CA-3, CA-7, CM-5, CM-6, CM-7, IA-2, IA-5, IA-12, RA-5, SA-3, SA-4, SA-8, SA-10, SA-11, SA-15, SA-17, SC-7, SC-28, SC-43, SI-4 |
| Techniques D3FEND (neo4j) | T1078 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-UAP | — |
