# N-PROTO-03 — Redirection vers de faux pairs

- **Cible** : Nœuds
- **Catégorie** : Menaces protocolaires
- **Identifiant** : N-PROTO-03

## Description
Un nœud oriente les requêtes de découverte vers des pairs contrôlés par l'attaquant.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Adversary-in-the-Middle | T1557 | Les réponses de découverte sont empoisonnées pour rediriger la victime vers des pairs contrôlés par l'attaquant. | Vérification par adressage-hash de contenu des shards obtenus quel que soit le pair, un pair malveillant ne pouvant fournir de ciphertext valide. |
| Rogue Domain Controller | T1207 | Les faux pairs annoncés se présentent comme des fournisseurs légitimes des données recherchées, en analogue P2P d'un contrôleur illégitime. | Codage d'effacement Reed-Solomon (`k=4`, `m=2`) permettant de reconstruire depuis d'autres pairs et réparation obligatoire contournant les pairs défaillants. |
| Acquire Infrastructure: Server | T1583.004 | L'attaquant déploie des nœuds dédiés pour capter les requêtes de découverte. | Identités auto-certifiantes par PoW et `ConnectionGater` avec blocklist par pair/sous-réseau limitant l'insertion de nœuds hostiles. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Adressage par hash de contenu | T1557 | D3-FH | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1207 | — | SC-36 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1583.004 | — | SC-5 |
| ConnectionGater / ResourceManager / ConnManager | T1583.004 | D3-NTF | SC-7 |
| Contrôles CTID (neo4j) | T1557 | — | AC-3, AC-4, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, SC-4, SC-7, SC-8, SC-23, SC-46, SI-3, SI-4, SI-12, SI-15 |
| Techniques D3FEND (neo4j) | T1557 | D3-EAL, D3-EDL, D3-FA, D3-ITF, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
