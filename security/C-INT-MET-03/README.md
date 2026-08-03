# C-INT-MET-03 — Fausse origine

- **Cible** : Clients
- **Catégorie** : Intégrité › Métadonnées
- **Identifiant** : C-INT-MET-03

## Description
Une donnée est présentée comme provenant d'un émetteur qui n'est pas le sien.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Social Engineering: Impersonation | T1684.001 | Un acteur usurpe l'identité d'un émetteur légitime pour faire accepter une donnée sous une fausse origine. | Signature Ed25519 de l'émetteur vérifiée à la réception et identité de stockage auto-certifiante par preuve de travail (argon2id) coûteuse à usurper. |
| Masquerading | T1036 | Une donnée se présente sous une provenance falsifiée pour tromper le client. | Adressage par hash de contenu et capacités signées liant chaque donnée à son propriétaire vérifiable. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Signatures / capacités Ed25519 | D3-MAN | AU-10 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | — | SC-5 |
| Adressage par hash de contenu | D3-FH | SI-7 |
