# N-ECO-04 — Externaliser clandestinement le stockage

- **Cible** : Nœuds
- **Catégorie** : Menaces économiques
- **Identifiant** : N-ECO-04

## Description
Un nœud délègue en secret le stockage à un tiers ou à un cloud, brisant les hypothèses d'indépendance et de localisation.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Trusted Relationship | T1199 | Le nœud s'appuie sur un tiers caché (hébergeur, cloud) pour tenir ses engagements, brisant l'hypothèse d'indépendance. | Confidentialité préservée quoi qu'il arrive : le tiers ne voit que du ciphertext opaque (chiffrement client-side AES-256-GCM) ; diversité de placement mesurée par sondes réseau, non par déclaration. |
| Proxy | T1090 | Analogue : le nœud relaie en secret les shards vers un backend externe au lieu de les stocker localement. | Sondes de possession recomputant le hash de contenu et mesure de latence/topologie pour détecter un backend distant ; quota et index de propriété tenus par le ledger. |
| Data from Cloud Storage | T1530 | Analogue : les données confiées finissent stockées sur un service cloud tiers, hors du modèle de menace revika. | Chiffrement client-side et encapsulation de capacité ML-KEM-768 : même exfiltré vers un cloud, le shard reste inexploitable sans la clé détenue côté User. |
