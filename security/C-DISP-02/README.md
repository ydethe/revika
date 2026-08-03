# C-DISP-02 — Multiplication des connexions

- **Cible** : Clients
- **Catégorie** : Disponibilité
- **Identifiant** : C-DISP-02

## Description
Un client ouvre un grand nombre de connexions pour épuiser les ressources de connexion des nœuds.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Endpoint Denial of Service: Service Exhaustion Flood | T1499.002 | La multiplication des connexions épuise le service de connexion des nœuds. | Plafonner les connexions via `ConnManager` (bornes low/high, période de grâce) dans `internal/net/defense.go`. |
| Endpoint Denial of Service: OS Exhaustion Flood | T1499.001 | Le grand nombre de connexions épuise les ressources système (descripteurs, mémoire) du nœud. | Imposer les limites du `ResourceManager` libp2p et bannir par pair/sous-réseau via `ConnectionGater`. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| ConnectionGater / ResourceManager / ConnManager | T1499.001, T1499.002 | D3-NTF | SC-7 |
