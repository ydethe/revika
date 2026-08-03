# C-INT-SIG-02 — Signature d'un contenu différent

- **Cible** : Clients
- **Catégorie** : Intégrité › Signatures
- **Identifiant** : C-INT-SIG-02

## Description
Une signature valide est présentée comme couvrant un contenu qu'elle ne couvre pas réellement.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Masquerading | T1036 | Un contenu falsifié est déguisé en contenu légitimement signé en réutilisant une signature valide hors de sa portée. | Signer non le contenu brut mais le hash de contenu du shard, de sorte que la signature ne vaut que pour l'objet exact adressé. |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Le lien signature↔contenu est détourné pour faire passer des données modifiées pour authentifiées. | Recomputer et comparer le hash de contenu à la vérification, tout écart entre le contenu servi et le hash signé étant rejeté. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Signatures / capacités Ed25519 | T1036 | D3-MAN | AU-10 |
| Adressage par hash de contenu | T1036 | D3-FH | SI-7 |
| Recompute du hash à la réception | T1565.001 | D3-FH | SI-7 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
