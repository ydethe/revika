# C-PROTO-03 — Ancienne version du protocole

- **Cible** : Clients
- **Catégorie** : Menaces protocolaires
- **Identifiant** : C-PROTO-03

## Description
Un client force l'usage d'une version obsolète du protocole pour bénéficier de ses faiblesses.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Weaken Encryption | T1600 | Le client tente un downgrade vers une version aux garanties cryptographiques ou protocolaires affaiblies. | Protocoles libp2p versionnés dont la négociation refuse les versions dépréciées, sur transport chiffré/authentifié imposant AES-256-GCM et ML-KEM-768. |
