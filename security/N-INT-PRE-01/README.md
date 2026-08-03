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
| Impersonation | T1656 | Analogue : le nœud feint la capacité de service d'un dépositaire légitime pour capter réputation/quota. | Réparation obligatoire sur ciphertext déterministe et probes périodiques : un dépositaire incapable de servir est détecté et ses shards régénérés ailleurs. |
