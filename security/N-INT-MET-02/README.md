# N-INT-MET-02 — Modification des timestamps

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Métadonnées
- **Identifiant** : N-INT-MET-02

## Description
Le nœud altère les horodatages d'écriture ou d'expiration afin de fausser l'ordre des événements ou la validité des baux.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Indicator Removal: Timestomp | T1070.006 | Le nœud falsifie les horodatages d'écriture ou d'expiration des baux pour brouiller la chronologie réelle des opérations. | Horloges/nonces/numéros de séquence signés côté client et TTL de baux portés par des jetons signés : un horodatage local non signé n'est pas source de vérité. |
| Data Manipulation: Stored Data Manipulation | T1565.001 | En modifiant les dates d'expiration dans le ledger, le nœud prolonge ou périme artificiellement des baux valides. | Baux à TTL ancrés sur des jetons d'accès signés à durée limitée + révocation : la validité d'un bail est vérifiée contre la signature, non contre l'horloge du nœud. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Anti-rejeu nonce/horloge/seq + TTL | T1070.006 | — | SC-23 |
| Capacités TTL court + révocation | T1565.001 | — | AC-3 |
| Contrôles CTID (neo4j) | T1565.001 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-8, CP-6, CP-7, CP-9, CP-10, SC-4, SC-7, SC-28, SC-36, SI-4, SI-7, SI-12, SI-16 |
| Techniques D3FEND (neo4j) | T1565.001 | D3-EAL, D3-EDL, D3-OSM | — |
