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

| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Chiffrement client-side AES-256-GCM | D3-MENCR | SC-28 |
| Encapsulation ML-KEM-768 (cap wrapping) | D3-MENCR | SC-12 |
| Signatures / capacités Ed25519 | D3-MAN | AU-10 |
