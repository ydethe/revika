# C-PROTO-05 — Déclaration mensongère de capacités

- **Cible** : Clients
- **Catégorie** : Menaces protocolaires
- **Identifiant** : C-PROTO-05

## Description
Un client annonce des capacités qu'il ne possède pas pour négocier un service inadapté.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Masquerading | T1036 | Le client se présente sous de fausses capacités lors de la négociation de service. | Négociation vérifiée cryptographiquement (capacités et identité auto-certifiées Ed25519/PoW), les prétentions non prouvées étant rejetées. |
| Impersonation | T1656 | Le client usurpe un profil de capacités pour obtenir un traitement indu. | Admission des écritures conditionnée à une preuve de travail (argon2id) et à une identité liée à la pubkey, rendant l'usurpation coûteuse et vérifiable. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Signatures / capacités Ed25519 | T1036 | D3-MAN | AU-10 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1656 | — | SC-5 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
