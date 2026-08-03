# N-INT-REG-05 — Rejeu d'événements

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Registre
- **Identifiant** : N-INT-REG-05

## Description
Un nœud réémet des événements de registre déjà valides pour les faire compter plusieurs fois.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Use Alternate Authentication Material | T1550 | Analogue de rejeu : le nœud réutilise un événement signé déjà valide pour le faire recompter. | Nonces, horodatages et numéros de séquence signés par entrée, avec déduplication côté ledger pour rejeter tout rejeu. |
| Transmitted Data Manipulation | T1565.002 | La réémission fausse la comptabilité en gonflant le décompte d'événements transmis au registre. | Idempotence des écritures adressées par hash de contenu ; les protocoles libp2p versionnés lient chaque message à un identifiant unique non rejouable. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Anti-rejeu nonce/horloge/seq + TTL | T1550 | — | SC-23 |
| Adressage par hash de contenu | T1565.002 | D3-FH | SI-7 |
| Protocoles versionnés + fail-closed | T1565.002 | — | SI-10 |
| Contrôles CTID (neo4j) | T1550 | — | AC-2, AC-3, AC-5, AC-6, CM-5, CM-6, IA-2 |
| Contrôles CTID (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-12 |
| Techniques D3FEND (neo4j) | T1550 | D3-EAL, D3-EDL, D3-LAM, D3-LFP, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1565.002 | D3-OSM | — |
