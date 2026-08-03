# N-ORG-GEO-02 — VPN/proxy

- **Cible** : Nœuds
- **Catégorie** : Menaces organisationnelles › Géolocalisation
- **Identifiant** : N-ORG-GEO-02

## Description
Un nœud masque sa localisation réelle via VPN ou proxy, faussant la diversité géographique perçue.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Multi-hop Proxy | T1090.003 | Le nœud passe par un VPN ou un proxy multi-sauts pour masquer sa localisation réelle et fausser la diversité perçue. | Estimer la position par triangulation de latence/RTT et corrélation d'AS/sous-réseau observés, plutôt que par l'adresse annoncée. |
| Virtual Private Server | T1583.003 | Le nœud est hébergé sur un VPS afin de présenter une localisation d'apparence différente de la sienne. | Détection de plages IP d'hébergeurs/VPS connus et placement keyé sur la diversité réseau réellement mesurée. |
| Masquerading | T1036 | L'ensemble simule une diversité géographique qui n'existe pas physiquement. | Codage d'effacement dispersant les shards sur des owners distincts, de sorte qu'une fausse diversité ne concentre pas tout `k` au même endroit réel. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Diversité de placement mesurée par le réseau | T1090.003, T1583.003 | — | SC-36 |
| Placement réparti sur owners indépendants | T1036 | — | SC-36 |
| Codage Reed-Solomon k=4/m=2 + réparation | T1036 | — | SC-36 |
| Contrôles CTID (neo4j) | T1090.003 | — | AC-3, AC-4, CA-7, CM-6, CM-7, SC-7, SI-15 |
| Contrôles CTID (neo4j) | T1036 | — | AC-2, AC-3, AC-6, CA-7, CM-2, CM-6, CM-7, IA-9, SI-3, SI-4, SI-7 |
| Techniques D3FEND (neo4j) | T1090.003 | D3-EAL, D3-EDL, D3-ITF, D3-OTF | — |
| Techniques D3FEND (neo4j) | T1036 | D3-EAL, D3-EDL, D3-FA, D3-LFP, D3-NTA, D3-OSM, D3-PA, D3-PM, D3-UAP | — |
