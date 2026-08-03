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
