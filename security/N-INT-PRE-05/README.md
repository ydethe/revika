# N-INT-PRE-05 — Falsification de preuves de disponibilité

- **Cible** : Nœuds
- **Catégorie** : Intégrité › Preuves
- **Identifiant** : N-INT-PRE-05

## Description
Un nœud fournit une preuve mensongère qu'il est disponible et joignable pour servir une donnée qu'il ne peut en réalité pas fournir.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Masquerading | T1036 | Le nœud se déclare joignable et apte à servir une donnée qu'il ne peut effectivement pas fournir. | Probes de disponibilité exigeant le renvoi réel du shard vérifié par hash, et non une simple attestation déclarative. |
| Social Engineering: Impersonation | T1684.001 | Analogue : le nœud usurpe le statut d'un dépositaire fonctionnel dans le calcul de placement/réparation. | Réparation obligatoire déclenchée dès qu'une probe échoue, régénérant les shards depuis les k survivants sur d'autres nœuds. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Sondes + défis de possession | T1036 | — | SI-7 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1684.001 | — | SC-36 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4 |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
