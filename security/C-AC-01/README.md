# C-AC-01 — Accès sans autorisation

- **Cible** : Clients
- **Catégorie** : Contrôle d'accès
- **Identifiant** : C-AC-01

## Description
Un client tente d'accéder à des données pour lesquelles il ne détient aucune capacité valide.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Data from Cloud Storage | T1530 | Le client cherche à lire des shards stockés sans capacité valide (analogue P2P du stockage cloud). | Chiffrement client-side avant émission : les nœuds ne voient que du ciphertext opaque, inexploitable sans la clé encapsulée ML-KEM-768. |
| Brute Force | T1110 | Le client tente de deviner ou forcer une capacité/clé d'accès. | Capacités signées Ed25519 requises et clés AES-256-GCM à haute entropie, rendant le forçage infaisable ; admission des lectures conditionnée à une capacité vérifiée. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Chiffrement client-side AES-256-GCM | T1530 | D3-MENCR | SC-28 |
| Encapsulation ML-KEM-768 (cap wrapping) | T1530 | D3-MENCR | SC-12 |
| Signatures / capacités Ed25519 | T1110 | D3-MAN | AU-10 |
| Contrôles CTID (neo4j) | T1530 | — | AC-2, AC-3, AC-4, AC-5, AC-6, AC-7, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-5, CM-6, CM-7, CM-8, IA-2, IA-3, IA-4, IA-5, IA-6, IA-8, RA-5, SC-4, SC-7, SI-4, SI-7, SI-12, SI-15 |
| Contrôles CTID (neo4j) | T1110 | — | AC-2, AC-3, AC-5, AC-6, AC-7, AC-20, CA-7, CM-2, CM-6, IA-2, IA-4, IA-5, IA-11, SI-4 |
| Techniques D3FEND (neo4j) | T1530 | D3-AL, D3-EAL, D3-EDL, D3-ITF, D3-LAM, D3-LFP, D3-NTA, D3-OSM, D3-OTF, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1110 | D3-AL, D3-EAL, D3-EDL, D3-LFP, D3-OSM, D3-UAP | — |
