# N-INT-MET-01 — Falsification des métadonnées

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Métadonnées
- **Identifiant** : N-INT-MET-01

## Description
Le nœud modifie les métadonnées associées aux shards (propriétaire, bail, quota, stripe) pour tromper les autres participants.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Le nœud falsifie dans son ledger SQLite les métadonnées de propriété, bail, quota ou stripe rattachées aux shards. | Métadonnées d'effacement signées (`stripe.Descriptor`, grant de réparation signé) : une métadonnée falsifiée invalide la signature Ed25519 et est rejetée. |
| Masquerading | T1036 | En réécrivant le propriétaire d'un shard, le nœud fait passer une donnée pour appartenant à un autre owner que le titulaire réel. | Propriété liée à la pubkey Ed25519 auto-certifiante de l'owner et capacités signées encapsulées ML-KEM-768 : l'appartenance n'est pas réattribuable localement par le nœud. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Métadonnées d'effacement signées (stripe.Descriptor) | T1565.001 | D3-MAN | SI-7 |
| Grant de réparation signé | T1565.001 | D3-MAN | AC-3 |
| Signatures / capacités Ed25519 | T1036 | D3-MAN | AU-10 |
| Encapsulation ML-KEM-768 (cap wrapping) | T1036 | D3-MENCR | SC-12 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-12, SI-16 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
