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

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Anti-rejeu nonce/horloge/seq + TTL | — | SC-23 |
| Capacités TTL court + révocation | — | AC-3 |
