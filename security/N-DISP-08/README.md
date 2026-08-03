# N-DISP-08 — Refus de maintenance

- **Cible** : Nœuds
- **Catégorie** : Disponibilité
- **Identifiant** : N-DISP-08

## Description
Un nœud ne participe pas aux opérations de réparation et de ré-encodage nécessaires au maintien de la redondance.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Inhibit System Recovery | T1490 | En s'abstenant de réparer et ré-encoder, le nœud laisse la redondance s'éroder et entrave le rétablissement. | Réparation obligatoire déclenchée par sondes, opérant sur ciphertext déterministe via un grant de réparation signé, et redistribuable à tout autre nœud. |
| Service Stop | T1489 | Analogue P2P : le nœud interrompt sa contribution au service de maintenance du stripe. | Métadonnées d'effacement signées (`stripe.Descriptor`) permettant à un pair coopératif de régénérer les shards manquants à leur adresse par hash. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Codage Reed-Solomon k=4/m=2 + réparation | T1490 | — | SC-36 |
| Sondes + défis de possession | T1490 | — | SI-7 |
| Grant de réparation signé | T1490 | D3-MAN | AC-3 |
| Métadonnées d'effacement signées (stripe.Descriptor) | T1489 | D3-MAN | SI-7 |
| Adressage par hash de contenu | T1489 | D3-FH | SI-7 |
