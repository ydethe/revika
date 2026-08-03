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

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Signatures / capacités Ed25519 | D3-MAN | AU-10 |
| Adressage par hash de contenu | D3-FH | SI-7 |
| Recompute du hash à la réception | D3-FH | SI-7 |
