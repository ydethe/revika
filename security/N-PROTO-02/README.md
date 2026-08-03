# N-PROTO-02 — Attaque Eclipse

- **Cible** : Nœuds
- **Catégorie** : Menaces protocolaires
- **Identifiant** : N-PROTO-02

## Description
Un nœud ou un groupe monopolise les connexions d'une victime pour contrôler sa vision du réseau et l'isoler des pairs honnêtes.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Adversary-in-the-Middle | T1557 | En monopolisant les connexions de la victime, l'attaquant s'interpose entre elle et le reste du réseau (attaque Eclipse). | Diversification des connexions et des buckets Kademlia du DHT `/revika`, ancrage sur des bootstrap de confiance et `ConnManager` maintenant des liens vers des pairs variés. |
| Rogue Domain Controller | T1207 | De faux pairs saturent la table de routage de la victime pour dominer sa vue du réseau. | Identités auto-certifiantes par preuve de travail (argon2id) renchérissant la création massive de pairs et `ConnectionGater` filtrant pairs/sous-réseaux suspects. |
| Establish Accounts | T1585 | L'attaquant crée en masse des identités de nœuds pour peupler l'entourage de la victime (Sybil). | Frein anti-Sybil par PoW sur l'identité de stockage et rate-limiting par-owner clé sur la pubkey Ed25519. |
| Acquire Infrastructure: Botnet | T1583.005 | Un ensemble de nœuds contrôlés est mobilisé pour encercler la victime. | Limites de connexions du `ResourceManager`/`ConnManager` et blocklist statique du `ConnectionGater` plafonnant l'emprise d'un même acteur. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| DHT /revika + diversité des pairs | T1557 | — | SC-36 |
| ConnectionGater / ResourceManager / ConnManager | T1207, T1583.005 | D3-NTF | SC-7 |
| Identité auto-certifiante PoW argon2id (anti-Sybil) | T1207, T1585 | — | SC-5 |
| Rate-limiting par-owner (pubkey Ed25519) | T1585 | D3-ITF | SC-5 |
| Contrôles CTID (neo4j) | T1557 | — | AC-3, AC-4, AC-16, AC-17, AC-18, AC-19, AC-20, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, SC-4, SC-7, SC-8, SC-23, SC-46, SI-3, SI-4, SI-7, SI-12, SI-15 |
| Techniques D3FEND (neo4j) | T1557 | D3-EAL, D3-EDL, D3-FA, D3-ITF, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM | — |
