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

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Sondes + défis de possession | T1036 | — | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1656 | — | SC-36 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
