# C-ECO-01 — Création massive de données

- **Cible** : Clients
- **Catégorie** : Menaces économiques
- **Identifiant** : C-ECO-01

## Description
Un client crée un volume massif de données pour épuiser les ressources ou le quota du réseau.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Application Exhaustion Flood | T1499.003 | Le client inonde les nœuds de créations pour épuiser leur stockage disponible. | Quotas par-owner et baux (leases) à TTL tenus par le ledger SQLite, plafonnant le stockage consommable par identité. |
| Resource Hijacking | T1496 | Le client accapare les ressources de stockage du réseau au détriment des autres. | Rate-limiting par-owner clé sur la pubkey Ed25519 et admission des écritures conditionnée à une preuve de travail (argon2id). |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Ledger SQLite par-owner + quotas/baux | T1499.003 | — | SC-6 |
| Rate-limiting par-owner (pubkey Ed25519) | T1496 | D3-ITF | SC-5 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1496 | — | SC-5 |
