# N-INT-REG-02 — Réécriture du registre

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Registre
- **Identifiant** : N-INT-REG-02

## Description
Un nœud tente de modifier a posteriori des entrées déjà inscrites dans le registre distribué.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Stored Data Manipulation | T1565.001 | Le nœud réécrit des entrées de registre déjà validées pour en changer le contenu historique. | Journal append-only signé et chaîné par hash : toute réécriture rompt la hash-chain et invalide les signatures Ed25519 en aval. |
| Indicator Removal | T1070 | La modification a posteriori vise à effacer ou maquiller la trace d'événements passés. | Réplication signée du ledger entre pairs et vérification de la continuité de la chaîne, empêchant l'acceptation d'une version altérée. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Journaux append-only chaînés + seq signés | — | AU-9 |
| Corroboration croisée inter-pairs du ledger | — | AU-6 |
