# C-INT-JRN-02 — Événements contradictoires

- **Cible** : Clients
- **Catégorie** : Intégrité › Journaux
- **Identifiant** : C-INT-JRN-02

## Description
Des entrées de journal contradictoires sont produites pour rendre l'historique inexploitable.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Des entrées contradictoires corrompent l'historique stocké pour le rendre inexploitable. | Chaîner les entrées par hash et les signer, tout ordre ou contenu incohérent avec la chaîne étant rejeté à la vérification. |
| Indicator Removal | T1070 | La contradiction sert à noyer et neutraliser les indicateurs authentiques d'une action. | Rattacher chaque entrée à une identité Ed25519 et à un numéro de séquence signé, permettant d'isoler les entrées non authentifiées. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Journaux append-only chaînés + seq signés | — | AU-9 |
| Signatures / capacités Ed25519 | D3-MAN | AU-10 |
