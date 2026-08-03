# N-INT-PRE-02 — Réutilisation d'anciennes preuves

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Preuves
- **Identifiant** : N-INT-PRE-02

## Description
Un nœud rejoue une preuve de stockage valide émise précédemment pour prétendre détenir encore la donnée.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Use Alternate Authentication Material | T1550 | Analogue de rejeu : le nœud réémet une preuve de stockage déjà valide pour paraître encore dépositaire. | Défis de possession à nonce aléatoire frais et à TTL, signés, rendant toute preuve antérieure inutilisable pour un nouveau défi. |
| Transmitted Data Manipulation | T1565.002 | La preuve rejouée fausse l'état de disponibilité transmis au vérifieur. | Liaison de chaque preuve à un challenge unique horodaté et signé (Ed25519), vérifiée puis rejetée si déjà consommée dans le ledger. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Sondes + défis de possession | — | SI-7 |
| Anti-rejeu nonce/horloge/seq + TTL | — | SC-23 |
