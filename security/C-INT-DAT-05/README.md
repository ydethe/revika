# C-INT-DAT-05 — Injection de données malveillantes

- **Cible** : Clients
- **Catégorie** : Intégrité › Données
- **Identifiant** : C-INT-DAT-05

## Description
Un attaquant insère dans le flux du client des données malveillantes destinées à être stockées ou traitées.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data Manipulation: Transmitted Data Manipulation | T1565.002 | L'attaquant injecte des shards illégitimes dans le flux d'écriture/lecture du client. | Recomputation du hash de contenu à la réception et AEAD AES-256-GCM rejetant tout shard non issu du chiffrement client-side. |
| Exploitation for Client Execution | T1203 | Les données malveillantes injectées visent à être traitées par le client pour déclencher un comportement non voulu. | Traitement des shards comme ciphertext opaque adressé par hash, vérifié avant tout déchiffrement, sans interprétation par les nœuds. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Recompute du hash à la réception | T1565.002 | D3-FH | SI-7 |
| Chiffrement client-side AES-256-GCM | T1565.002 | D3-MENCR | SC-28 |
| Nœud « dumb/untrusted » + re-vérification côté User | T1203 | — | SA-8 |
| Contrôles CTID (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-12 |
| Contrôles CTID (neo4j) | T1203 | — | AC-4, AC-6, CA-7, CM-8, SC-2, SC-3, SC-7, SC-18, SC-29, SC-30, SC-39, SC-44, SI-2, SI-3, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1565.002 | D3-OSM | — |
| Techniques D3FEND (neo4j) | T1203 | D3-EI, D3-FA, D3-ITF, D3-LFP, D3-NI, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM, D3-SCP, D3-UAP | — |
