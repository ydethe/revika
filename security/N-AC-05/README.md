# N-AC-05 — Falsifier l'identité d'un demandeur

- **Cible** : Nœuds
- **Catégorie** : Contrôle d'accès
- **Identifiant** : N-AC-05

## Description
Un nœud attribue à une requête une identité de demandeur différente pour contourner les contrôles d'accès.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Social Engineering: Impersonation | T1684.001 | Une requête se voit attribuer une identité de demandeur usurpée afin de bénéficier des droits d'un autre owner. | Liaison cryptographique de chaque requête à une pubkey Ed25519 auto-certifiante, l'identité ne pouvant être affirmée qu'en prouvant la possession de la clé privée. |
| Masquerading | T1036 | Le nœud présente une identité de demandeur falsifiée pour franchir les contrôles d'accès. | Jetons d'accès signés liés à l'identité du demandeur et vérifiés à la source, empêchant toute réattribution d'identité côté nœud. |
| Forge Web Credentials | T1606 | Une preuve d'identité de demandeur est forgée pour se faire passer pour un owner autorisé. | Authentification par signature Ed25519 sur nonce, infalsifiable sans la clé privée, plutôt que par un identifiant déclaratif. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Signatures / capacités Ed25519 | T1684.001, T1036, T1606 | D3-MAN | AU-10 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| Contrôles CTID (neo4j) | T1606 | — | AC-2, AC-3, AC-5, AC-6, SC-17, SI-2 |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1606 | D3-EAL, D3-EDL, D3-LFP, D3-UAP | — |
