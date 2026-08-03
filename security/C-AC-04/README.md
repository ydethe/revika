# C-AC-04 — Escalade de privilèges

- **Cible** : Clients
- **Catégorie** : Contrôle d'accès
- **Identifiant** : C-AC-04

## Description
Un client transforme un accès limité en un accès plus étendu que celui qui lui a été accordé.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Abuse Elevation Control Mechanism | T1548 | Le client détourne le mécanisme d'octroi de capacités pour étendre son périmètre au-delà de l'accordé. | Capacités liées cryptographiquement à un périmètre précis (read-capability = localisation manifest + clé encapsulée ML-KEM), non extensibles sans une nouvelle capacité signée. |
| Exploitation for Privilege Escalation | T1068 | Le client exploite une faille du contrôle d'accès pour obtenir des droits supérieurs. | Contrôle d'accès porté par la cryptographie plutôt que par des rôles serveur, et propriété/quota arbitrés par le ledger SQLite par-owner. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Encapsulation ML-KEM-768 (cap wrapping) | T1548 | D3-MENCR | SC-12 |
| Signatures / capacités Ed25519 | T1548 | D3-MAN | AU-10 |
| Ledger SQLite par-owner + quotas/baux | T1068 | — | SC-6 |
| Contrôles CTID (neo4j) | T1548 | — | AC-2, AC-3, AC-5, AC-6, AC-16, CA-7, CM-2, CM-3, CM-5, CM-6, CM-7, CM-8, IA-2, RA-5, SC-18, SC-34, SI-2, SI-3, SI-4, SI-7, SI-12, SI-16 |
| Contrôles CTID (neo4j) | T1068 | — | AC-2, AC-4, AC-6, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, RA-10, SC-2, SC-3, SC-7, SC-18, SC-30, SC-39, SI-2, SI-3, SI-4, SI-5, SI-7 |
| Techniques D3FEND (neo4j) | T1548 | D3-EAL, D3-EDL, D3-FA, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1068 | D3-EI, D3-FA, D3-ITF, D3-LFP, D3-NI, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM, D3-SCP, D3-UAP | — |
