# N-PROTO-04 — Logiciel modifié

- **Cible** : Nœuds
- **Catégorie** : Menaces protocolaires
- **Identifiant** : N-PROTO-04

## Description
Un opérateur exécute une version altérée du logiciel de nœud qui dévie du protocole attendu.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Compromise Host Software Binary | T1554 | L'opérateur exécute un binaire de nœud modifié qui s'écarte du protocole revika attendu. | Modèle de nœud « dumb, untrusted » : la confidentialité repose sur le chiffrement client-side et l'adressage-hash, un nœud dévoyé ne voyant que du ciphertext opaque. |
| Supply Chain Compromise: Compromise Software Supply Chain | T1195.002 | Une version altérée du logiciel est distribuée puis déployée par des opérateurs. | Reproductibilité de build et vérification d'intégrité des artefacts, avec toolchain Go épinglée (`go 1.26`) et dépendances pinnées. |
| Disable or Modify Tools | T1685 | Le logiciel modifié désactive les contrôles de conformité que le nœud devrait appliquer. | Conception qui ne fait pas dépendre la sécurité du bon comportement d'un nœud : effacement Reed-Solomon + réparation obligatoire tolèrent un nœud déviant. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Nœud « dumb/untrusted » + re-vérification côté User | — | SA-8 |
| Build reproductible / chaîne d'appro. épinglée | — | SR-4 |
| Codage Reed-Solomon k=4/m=2 + réparation | — | SC-36 |
