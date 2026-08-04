# C-INT-MET-03 — Fausse origine

- **Cible** : Clients
- **Catégorie** : Intégrité › Métadonnées
- **Identifiant** : C-INT-MET-03

## Description
Une donnée est présentée comme provenant d'un émetteur qui n'est pas le sien.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Impersonation | T1656 | Un acteur usurpe l'identité d'un émetteur légitime pour faire accepter une donnée sous une fausse origine. | Signature Ed25519 de l'émetteur vérifiée à la réception et identité de stockage auto-certifiante par preuve de travail (argon2id) coûteuse à usurper. |
| Masquerading | T1036 | Une donnée se présente sous une provenance falsifiée pour tromper le client. | Adressage par hash de contenu et capacités signées liant chaque donnée à son propriétaire vérifiable. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Signatures / capacités Ed25519 | T1656, T1036 | D3-MAN | AU-10 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1656 | — | SC-5 |
| Adressage par hash de contenu | T1036 | D3-FH | SI-7 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
