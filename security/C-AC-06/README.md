# C-AC-06 — Partage de droits

- **Cible** : Clients
- **Catégorie** : Contrôle d'accès
- **Identifiant** : C-AC-06

## Description
Un client redistribue à des tiers non autorisés les droits d'accès qui lui ont été conférés.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Use Alternate Authentication Material | T1550 | Le client transmet à un tiers le matériel d'authentification/capacité qu'il détient. | Partage strictement par encapsulation ML-KEM-768 à la pubkey du destinataire (jamais copie du plaintext) et capacités révocables à TTL. |
| Trusted Relationship | T1199 | Le client abuse de la confiance qui lui a été accordée pour propager l'accès hors périmètre. | Journal d'audit append-only signé et chaîné traçant les partages, avec révocation et rotation des capacités concernées. |
