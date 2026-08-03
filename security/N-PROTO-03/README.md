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

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Adressage par hash de contenu | D3-FH | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | — | SC-36 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | — | SC-5 |
| ConnectionGater / ResourceManager / ConnManager | D3-NTF | SC-7 |
