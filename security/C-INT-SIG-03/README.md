# C-INT-SIG-03 — Rejeu

- **Cible** : Clients
- **Catégorie** : Intégrité › Signatures
- **Identifiant** : C-INT-SIG-03

## Description
Une signature légitime est rejouée dans un contexte différent pour autoriser une opération non voulue.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Analogue de rejeu : un jeton d'accès signé légitime est réutilisé dans un autre contexte pour autoriser une opération. | Émettre des jetons d'accès signés à durée limitée (TTL) et liés au contexte, avec nonces/numéros de séquence signés pour l'anti-rejeu. |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | La rediffusion d'un message signé en vol détourne son autorité vers une opération non voulue. | Inclure horloge/nonce dans le message signé et transporter via canal libp2p chiffré/authentifié, rejetant tout message hors fenêtre ou déjà vu. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Anti-rejeu nonce/horloge/seq + TTL | T1550.001, T1565.002 | — | SC-23 |
| Transport libp2p chiffré / authentifié | T1565.002 | D3-MENCR | SC-8 |
