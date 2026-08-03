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

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Signatures / capacités Ed25519 | D3-MAN | AU-10 |
