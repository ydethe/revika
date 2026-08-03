# C-AC-03 — Jeton falsifié

- **Cible** : Clients
- **Catégorie** : Contrôle d'accès
- **Identifiant** : C-AC-03

## Description
Un client présente un jeton d'accès forgé pour obtenir un service.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Forge Web Credentials | T1606 | Le client fabrique un jeton d'accès qu'aucune autorité légitime n'a émis (analogue P2P d'un jeton web forgé). | Jetons et capacités signés Ed25519 : toute signature invalide est rejetée, la forge exigeant la clé privée du propriétaire. |
| Use Alternate Authentication Material: Application Access Token | T1550.001 | Le client soumet le jeton forgé au nœud pour obtenir le service. | Vérification systématique de la signature du jeton côté nœud avant tout service, adossée au ledger de propriété. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Signatures / capacités Ed25519 | D3-MAN | AU-10 |
| Ledger SQLite par-owner + quotas/baux | — | SC-6 |
