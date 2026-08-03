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
