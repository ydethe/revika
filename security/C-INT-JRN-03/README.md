# C-INT-JRN-03 — Bruit massif

- **Cible** : Clients
- **Catégorie** : Intégrité › Journaux
- **Identifiant** : C-INT-JRN-03

## Description
Le journal est noyé sous un volume massif d'événements sans intérêt pour masquer une action.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Disable or Modify Tools | T1685 | Le bruit massif d'événements masque les indicateurs de l'action réelle. | Rate-limiter la génération d'événements par-owner (clé sur la pubkey Ed25519) pour brider les flots destinés à noyer le journal. |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | Le volume d'événements sature la capacité de journalisation/analyse. | Appliquer quotas par-owner et limites `ResourceManager`/`ConnManager` pour plafonner le débit d'entrées émises. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Rate-limiting par-owner (pubkey Ed25519) | T1685 | D3-ITF | SC-5 |
| Ledger SQLite par-owner + quotas/baux | T1499.003 | — | SC-6 |
| ConnectionGater / ResourceManager / ConnManager | T1499.003 | D3-NTF | SC-7 |
