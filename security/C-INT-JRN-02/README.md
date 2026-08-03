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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Journaux append-only chaînés + seq signés | T1565.001 | — | AU-9 |
| Signatures / capacités Ed25519 | T1070 | D3-MAN | AU-10 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-7, SI-12, SI-16 |
| Contrôles CTID (neo4j) | T1070 | — | AC-2, AC-3, AC-5, AC-6, AC-16, AC-17, AC-18, CA-7, CM-2, CM-6, CP-6, CP-7, CP-9, SC-4, SC-36, SI-3, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| Techniques D3FEND (neo4j) | T1070 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
