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
