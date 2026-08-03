# C-CONF-03 — Observation des temps de réponse

- **Cible** : Clients
- **Catégorie** : Confidentialité
- **Identifiant** : C-CONF-03

## Description
L'analyse des latences des opérations client révèle des informations telles que la présence en cache, la taille ou le chemin d'accès.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Network Sniffing | T1040 | L'observateur mesure les latences des requêtes de shards sur le réseau libp2p (analogue de canal auxiliaire temporel) pour déduire taille et cache. | Transport chiffré/authentifié et récupération parallèle des `k` shards Reed-Solomon lissant les temps de réponse observables. |
| Gather Victim Host Information | T1592 | Les écarts de latence révèlent l'état de cache et le chemin d'accès côté hôte. | Rate-limiting par-pair (`internal/net/defense.go`) et normalisation des réponses limitant le signal temporel exploitable. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Transport libp2p chiffré / authentifié | T1040 | D3-MENCR | SC-8 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1040 | — | SC-36 |
| Rate-limiting par-owner (pubkey Ed25519) | T1592 | D3-ITF | SC-5 |
| Contrôles CTID (neo4j) | T1040 | — | AC-16, AC-17, AC-18, AC-19, CM-7, IA-2, IA-5, SC-4, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1040 | D3-OSM | — |
