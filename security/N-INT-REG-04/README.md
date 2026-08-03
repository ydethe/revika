# N-INT-REG-04 — Création d'événements fictifs

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Registre
- **Identifiant** : N-INT-REG-04

## Description
Un nœud inscrit dans le registre des événements qui n'ont jamais eu lieu (faux stockage, faux transfert).

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Stored Data Manipulation | T1565.001 | Le nœud fabrique des entrées de registre (faux stockage, faux transfert) sans réalité sous-jacente. | Chaque événement doit référencer un shard vérifiable par hash de contenu et une capacité/grant signé, sinon il est rejeté. |
| Masquerading | T1036 | Les faux événements font passer une activité inexistante pour une opération légitime de stockage ou de transfert. | Corroboration croisée : un événement de stockage n'est admis qu'après preuve de détention vérifiable par le pair de contrôle. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Adressage par hash de contenu | T1565.001 | D3-FH | SI-7 |
| Signatures / capacités Ed25519 | T1565.001 | D3-MAN | AU-10 |
| Corroboration croisée inter-pairs du ledger | T1036 | — | AU-6 |
| Sondes + défis de possession | T1036 | — | SI-7 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-3, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
