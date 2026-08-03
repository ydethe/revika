# N-INT-PRE-01 — Fausses preuves de stockage

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Preuves
- **Identifiant** : N-INT-PRE-01

## Description
Un nœud produit une preuve de stockage sans réellement détenir la donnée correspondante.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Masquerading | T1036 | Le nœud se présente comme détenteur conforme d'un shard alors qu'il ne le stocke pas. | Preuve de possession par défi-réponse recalculant le hash de contenu du shard, impossible à satisfaire sans détenir les octets exacts. |
| Social Engineering: Impersonation | T1684.001 | Analogue : le nœud feint la capacité de service d'un dépositaire légitime pour capter réputation/quota. | Réparation obligatoire sur ciphertext déterministe et probes périodiques : un dépositaire incapable de servir est détecté et ses shards régénérés ailleurs. |

## Correspondance cadres de défense

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Sondes + défis de possession | — | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | — | SC-36 |
