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

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Chiffrement client-side AES-256-GCM | T1199, T1530 | D3-MENCR | SC-28 |
| Diversité de placement mesurée par le réseau | T1199 | — | SC-36 |
| Sondes + défis de possession | T1090 | — | SI-7 |
| Ledger SQLite par-owner + quotas/baux | T1090 | — | SC-6 |
| Encapsulation ML-KEM-768 (cap wrapping) | T1530 | D3-MENCR | SC-12 |
| Contrôles CTID (neo4j) | T1199 | — | AC-3, AC-4, AC-6, AC-8, CM-6, CM-7, SC-7, SC-46 |
| Contrôles CTID (neo4j) | T1530 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-7, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-5, CM-6, CM-7, CM-8, IA-2, IA-3, IA-4, IA-5, IA-6, IA-8, RA-5, SC-4, SC-7, SI-4, SI-7, SI-12, SI-15 |
| Contrôles CTID (neo4j) | T1090 | — | AC-3, AC-4, CA-7, CM-2, CM-6, CM-7, SC-7, SC-8, SI-3, SI-4, SI-15 |
| Techniques D3FEND (neo4j) | T1199 | D3-EAL, D3-EDL, D3-ITF, D3-LFP, D3-OTF, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1530 | D3-AL, D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1090 | D3-EAL, D3-EDL, D3-FA, D3-ITF, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
