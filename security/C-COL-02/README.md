# C-COL-02 — Collusion avec des nœuds

- **Cible** : Clients
- **Catégorie** : Collusion
- **Identifiant** : C-COL-02

## Description
Un client s'entend avec des nœuds pour obtenir un traitement de faveur ou tromper les audits.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Trusted Relationship | T1199 | Le client exploite une entente avec des nœuds pour obtenir un traitement de faveur. | Modèle de nœud « dumb » et non fiable : ils ne voient que du ciphertext opaque adressé par hash, sans pouvoir accorder de privilège sur le contenu. |
| Disable or Modify Tools: Disable or Modify Cloud Log | T1685.002 | La collusion vise à falsifier ou masquer les journaux d'audit des nœuds. | Journaux d'audit append-only signés et chaînés (hash-chain) détectant réécriture/omission, et vérification indépendante des shards par recomputation du hash. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Nœud « dumb/untrusted » + re-vérification côté User | — | SA-8 |
| Journaux append-only chaînés + seq signés | — | AU-9 |
| Recompute du hash à la réception | D3-FH | SI-7 |
