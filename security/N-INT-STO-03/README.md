# N-INT-STO-03 — Fourniture d'une ancienne version (rollback)

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Stockage
- **Identifiant** : N-INT-STO-03

## Description
Le nœud sert délibérément une version périmée d'un shard ou d'un manifeste, faisant régresser l'état visible par le client.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Stored Data Manipulation | T1565.001 | Le nœud restitue une révision antérieure (rollback) d'un shard ou manifeste au lieu de l'état courant, manipulant la donnée servie. | Manifestes signés Ed25519 portant un numéro de version/séquence : un rollback est détecté par régression du numéro signé côté client. |
| Use Alternate Authentication Material | T1550 | Analogue de rejeu : réservir une version passée valablement signée revient à rejouer un état authentifié périmé. | Nonces/numéros de séquence signés et jetons à TTL borné : un état expiré ou hors-séquence est refusé, cassant le rejeu. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Manifeste signé Ed25519 versionné | T1565.001 | D3-MAN | SI-7 |
| Anti-rejeu nonce/horloge/seq + TTL | T1550 | — | SC-23 |
