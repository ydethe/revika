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

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Signatures / capacités Ed25519 | T1606 | D3-MAN | AU-10 |
| Ledger SQLite par-owner + quotas/baux | T1550.001 | — | SC-6 |
| Contrôles CTID (neo4j) | T1606 | — | AC-2, AC-3, AC-5, AC-6, SC-17, SI-2 |
| Contrôles CTID (neo4j) | T1550.001 | — | AC-16, AC-17, AC-19, AC-20, CM-2, CM-6, CM-10, CM-11, IA-2, IA-4, SC-8, SC-28, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1606 | D3-EAL, D3-EDL, D3-LFP, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1550.001 | D3-OSM | — |
