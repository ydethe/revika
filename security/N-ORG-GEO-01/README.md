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
