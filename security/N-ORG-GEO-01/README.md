# N-ORG-GEO-01 — Fausser sa localisation

- **Cible** : Nœuds
- **Catégorie** : Menaces organisationnelles › Géolocalisation
- **Identifiant** : N-ORG-GEO-01

## Description
Un nœud déclare une position géographique erronée pour satisfaire des contraintes de répartition.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Masquerading | T1036 | Le nœud auto-déclare un attribut de position géographique falsifié pour satisfaire les contraintes de répartition. | Ne pas se fier à la géoloc auto-déclarée : dériver la position via sondes de latence/topologie et sous-réseau/AS observé au niveau libp2p. |
| Transmitted Data Manipulation | T1565.002 | Analogue : la métadonnée de localisation transmise à la politique de placement est manipulée en transit par le nœud émetteur. | Politique de placement basée sur des mesures réseau vérifiables plutôt que sur des métadonnées déclaratives, et diversité keyée sur la pubkey Ed25519. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Diversité de placement mesurée par le réseau | T1036, T1565.002 | — | SC-36 |
| Placement réparti sur owners indépendants | T1565.002 | — | SC-36 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| Contrôles CTID (neo4j) | T1565.002 | — | AC-16, AC-17, AC-18, AC-19, AC-20, CM-2, CM-6, CM-8, SC-4, SI-4, SI-7, SI-12 |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1565.002 | D3-OSM | — |
