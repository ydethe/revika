# Mécanismes de défense – Revika

## Objectif

Ce document décrit, **mécanisme par mécanisme**, les défenses réellement implémentées
dans revika et relie chacune aux scénarios d'attaque de [`Security.md`](./Security.md).
C'est la lecture « par la défense » ; la lecture « par la menace » (une fiche par
scénario, avec la cartographie MITRE ATT&CK détaillée) vit dans l'arborescence
[`security/`](./README.md), et le catalogue canonique des *primitives* de défense (P1–P27,
avec leurs correspondances D3FEND / NIST SP 800-53) est dans
[`frameworks.md`](./frameworks.md). Les trois documents se recoupent :

- **Ici** : comment le mécanisme fonctionne, où il vit dans le code, ce qu'il couvre.
- **`frameworks.md`** : à quels cadres reconnus chaque primitive `Pn` se rattache.
- **`security/<ID>/README.md`** : le détail ATT&CK technique par technique d'un scénario.

Le plan suit la demande : **d'abord les défenses côté nœud**, puis **les défenses côté
client**. Le classement se fait selon *où le mécanisme s'exécute*. Rappel du principe
directeur ([Architecture.md](../Architecture.md), [CLAUDE.md](../CLAUDE.md)) : **un nœud est
un magasin de blobs bête et non fiable** — toute l'intelligence (chunking, chiffrement,
clés, partage) est côté client ; un nœud n'est jamais fait confiance pour la
*confidentialité*, seulement pour la *disponibilité*. Beaucoup de scénarios ciblant les
nœuds (`N-CONF-*`, `N-INT-STO-*`) sont donc neutralisés par des mécanismes qui s'exécutent
côté client — ils sont traités dans la partie client et rappelés en renvoi.

> **Statut.** Revika est en développement. Ce document distingue explicitement ce qui est
> **implémenté** de ce qui est **différé** (couches anti-Sybil globale, réputation,
> incitations économiques, journal distribué corroboré — cf. Architecture.md §5). La section
> [Couverture et angles morts](#couverture-et-angles-morts) récapitule les scénarios non ou
> partiellement couverts, pour ne pas laisser croire à une protection qui n'existe pas.

---

# 1. Défenses côté nœud

Mécanismes qui s'exécutent dans le démon `revika-node` (`cmd/revika-node`,
`internal/net`, `internal/ledger`, `internal/repair`). Ils protègent la **disponibilité**
du nœud et du réseau, l'**intégrité** des shards au repos et à la restitution, et
l'**admission** des écritures — sans jamais déchiffrer ni interpréter un shard.

## 1.1 Magasin auto-vérifiant adressé par hash de contenu — P4, P5

`internal/store` (`Store.Get` re-hache le contenu et renvoie `ErrCorrupt` si l'empreinte
ne correspond pas au `ShardID` ; `ShardID = sha256`). Côté réception réseau, le serveur
(`internal/net/server.go`) et le client (`NetStore.putRaw`, `internal/net/client.go`)
vérifient que le CID annoncé correspond au contenu réellement stocké/servi. Un shard est
donc **infalsifiable en place** : toute altération sur disque casse la correspondance
CID↔contenu et est détectée à la lecture suivante, ce qui déclenche la réparation (§1.3).

- **Scénarios couverts** : [N-INT-STO-01](./N-INT-STO-01/) (altération d'un shard),
  [N-INT-STO-02](./N-INT-STO-02/) (shard corrompu servi),
  [N-INT-STO-04](./N-INT-STO-04/) (réorganisation locale — le CID reste l'adresse, la
  disposition physique est indifférente).

## 1.2 Preuve de travail à l'admission des écritures — P9

`Server.enforcePoW` (`internal/net/server.go:164`) n'admet un PUT d'un *owner frais* que si
sa clé de signature Ed25519 satisfait la difficulté PoW locale (`-pow-difficulty`, puzzle
Argon2id, `internal/cap/pow.go`). La clé de signature est **auto-certifiante** : elle est
broyée jusqu'à ce que sa pubkey hache sous la cible, si bien que re-miner une identité
bannie coûte du CPU, pas des millisecondes. La politique d'admission est propagée du nœud
*seed* aux nœuds *joignants* via `/revika/params` (`net.FetchNodePolicy`), la valeur la plus
stricte l'emportant. Les flux de maintenance autorisés par *grant* (réparation,
rééquilibrage) et les DELETE sont **exemptés** — sinon la durabilité serait prise en otage.

- **Scénarios couverts** : [N-ORG-SYB-01](./N-ORG-SYB-01/) (création de faux nœuds —
  renchérie, non éliminée), [N-DISP-07](./N-DISP-07/) (saturation — le PoW plafonne le débit
  d'admission de charge neuve), [C-ECO-01](./C-ECO-01/)/[C-ECO-04](./C-ECO-04/) (création
  massive de données / ressources gratuites, renchéries à l'admission).
- **Limite** : bannir par identité reste faible tant que les identités sont libres à créer ;
  le PoW relève le coût, l'anti-Sybil P2P complet est différé (§5).

## 1.3 Codage d'effacement, réparation et rééquilibrage — P6, P14, P16

Chaque fichier est erasure-codé Reed-Solomon (`internal/erasure`, `k=4`/`m=2` par défaut :
`k` données + `m` parité, `k` quelconques reconstruisent). `internal/repair` +
`internal/net/repair.go` (`RepairStore`) énumèrent les stripes du ledger, sondent la
survie des shards et **régénèrent** ceux qui manquent — `erasure.Encode` étant
**déterministe**, un shard régénéré reproduit exactement son adresse de contenu, sans jamais
déchiffrer (réparation sur ciphertext, autorisée par *grant* signé, §1.7). Le rééquilibrage
(`internal/net/rebalance.go`, diffusion pairwise §3.4) diffuse la charge en
**make-before-break** et n'est jamais destructeur avant confirmation.

Deux gardes durcissent le rééquilibrage, toutes deux indépendantes de l'identité (donc
tenables face au Sybil) :

- **`confirmStored`** (`rebalance.go:305`, GUARD1) : défie le pair de prouver qu'il détient
  *exactement* le shard (nonce frais) **avant** de libérer la copie source (release
  probe-gated).
- **`peerStripeLoad`** (`rebalance.go:320`, GUARD2) : plafonne la concentration à ≤ `m`
  shards d'une même stripe par nœud, pour qu'aucun nœud unique ne puisse en faisant tomber
  ses copies détruire une stripe.

- **Scénarios couverts** : [N-DISP-01](./N-DISP-01/) (suppression d'un shard : la réparation
  reconstitue, la garde de concentration limite l'impact d'un nœud), [N-INT-STO-02](./N-INT-STO-02/)
  (shard corrompu : décodage à partir des `k` sains), [N-DISP-07](./N-DISP-07/)/[N-DISP-05](./N-DISP-05/)
  (saturation / partition : servir depuis d'autres nœuds), [N-ORG-SYB-02](./N-ORG-SYB-02/)
  (collusion de nœuds : la garde de concentration borne ce qu'un groupe colocalisé détient
  d'une même stripe).

## 1.4 Sondes et défis de possession — P14

`ProbeProtocol` (`internal/net/proto.go`, `NonceSize=32`) : le vérifieur envoie un nonce
frais, le détenteur doit renvoyer `SHA256(nonce|shard)` en temps constant
(`NetStore.Probe`). Impossible de répondre sans détenir le shard, et impossible de rejouer
une réponse (nonce à usage unique). Deux consommateurs :

- **`confirmStored`** dans le rééquilibrage (§1.3), qui gate la libération.
- **Vérification de possession en réparation** (`RepairStore.SetVerifyPossession`,
  `-repair-verify`, `repair.go:65`) : à la demande, la survie d'un shard n'est plus le
  simple octet de présence `Store.Has` mais une **preuve de récupération** (fetch +
  auto-vérification d'adresse de contenu), ce qui attrape un nœud qui *ment* sur ce qu'il
  détient.

- **Scénarios couverts** : [N-INT-PRE-01](./N-INT-PRE-01/) (fausses preuves de stockage),
  [N-INT-PRE-02](./N-INT-PRE-02/) (réutilisation d'anciennes preuves — nonce frais),
  [N-INT-PRE-04](./N-INT-PRE-04/) (preuve sans données — le fetch le révèle),
  [N-INT-PRE-05](./N-INT-PRE-05/) (fausse disponibilité), [N-DISP-08](./N-DISP-08/) (refus de
  maintenance — un mensonge de possession devient une infraction, §1.6).

## 1.5 Ledger par-owner : propriété, baux, quotas — P13

`internal/ledger` (SQLite `modernc.org/sqlite`, `.revika/ledger/ledger.db` — **pas** une
blockchain) est l'arbitre unique de la propriété et des ressources d'un nœud : tables
`shards`/`owners`/`accounts`/`stripes`, quotas par-owner (`QuotaBytes`), baux TTL
(`LeaseTTL`), GC des baux expirés. Le `Server` est **ledger-gated** : un PUT frais est
refusé si l'owner dépasse son quota (`shard.put.rejected reason=quota`). Le déduplication
par adresse de contenu est comptée par refcount multi-owner. La ligne de stripe stocke le
*grant* qui autorise les mouvements de maintenance sans clé User (§1.7).

- **Scénarios couverts** : [N-DISP-07](./N-DISP-07/) (saturation : le quota borne le volume
  par owner), [C-ECO-01](./C-ECO-01/)/[C-ECO-02](./C-ECO-02/)/[C-ECO-03](./C-ECO-03/)
  (création massive / multiplication / cycles create-delete, bornés par quota et baux),
  [C-DISP-04](./C-DISP-04/) (demandes massives de reconstruction, bornées par le compte
  d'owner).

## 1.6 Détecteur d'abus de maintenance + blocklist persistante — P10, P11, P14

`internal/net/abuse.go` (`AbuseMonitor`) observe les deux flux de maintenance qu'un pair
dirige contre ce nœud et bannit localement l'abuseur, en agissant **uniquement** sur des
métadonnées de connexion/identité (jamais sur le contenu) :

- **Rééquilibrage trop rapide** (`ReasonRebalance`) : des sweeps arrivant plus vite que
  `interval − tolerance` ; une infraction suffit (les PUT d'un même sweep sont coalescés).
- **Mensonges de possession** : échecs répétés de preuve à nonce frais, comptés en *strikes*
  décroissants (défaut : 3 dans une fenêtre de décroissance).

Un octet `MoveReason` en fin de trame sur `/revika/shard/1.2.0` distingue un mouvement de
rééquilibrage policé d'une régénération de réparation exemptée de cadence. Les bans sont
ajoutés à une blocklist **runtime-mutable et persistante** (`net.Blocklister`,
`blocklist.auto`) qui s'unit à la blocklist statique de l'opérateur (`-blocklist`) et est
rechargée au redémarrage. Ce réglage anti-abus est une défense **locale**, jamais héritée du
bootstrap ni ignorée sur un nœud joignant.

- **Scénarios couverts** : [N-DISP-04](./N-DISP-04/) (ralentissement / abus de cadence),
  [N-DISP-08](./N-DISP-08/) (refus de maintenance), [N-INT-PRE-01](./N-INT-PRE-01/)/[N-INT-PRE-04](./N-INT-PRE-04/)
  (mensonges de possession sanctionnés), [N-PROTO-02](./N-PROTO-02/)/[N-PROTO-03](./N-PROTO-03/)
  (pairs malveillants isolés par blocklist).

## 1.7 Grant de réparation signé + descripteur de stripe signé — P20, P21

`internal/stripe` : `BuildGrant`/`VerifyGrant` (signature Ed25519 sur `domaine|expiry|desc`)
autorisent un mouvement de reconstruction **sur ciphertext déterministe** sans jamais
révéler la clé de déchiffrement ; le `Descriptor{K,M,Shards}` (métadonnées d'effacement non
confidentielles, **aucune clé**) est signé, si bien qu'une falsification invalide la
signature. Le nœud vérifie le grant avant d'accepter un PUT de maintenance ; c'est ce qui
distingue une écriture de maintenance légitime d'une injection.

- **Scénarios couverts** : [N-AC-02](./N-AC-02/) (accorder un accès sans autorisation — un
  mouvement sans grant valide est refusé), [N-INT-MET-01](./N-INT-MET-01/) (falsification des
  métadonnées d'effacement).
- **Limite** : l'expiration de grant `0` = jamais, la révocation de grant est **TODO**
  (`internal/stripe`).

## 1.8 Rate-limiting d'écriture par-owner — P10

`internal/net/ratelimit.go` (`OwnerRateLimiter`) : token bucket par owner (clé = pubkey
Ed25519 récupérée du token d'auth) refusant les PUT/DELETE au-delà de `-write-rate` /
`-write-burst` avec `statusRateLimited` (`proto.go:99`). C'est le **plafond de débit** qui
complète le quota de stockage (plafond de *volume*, §1.5). Les écritures de maintenance
autorisées par grant sont exemptées. Optionnel, désactivé par défaut ; défense locale.

- **Scénarios couverts** : [N-DISP-07](./N-DISP-07/) (saturation par flood d'écritures),
  [C-DISP-01](./C-DISP-01/) (flood), [C-DISP-02](./C-DISP-02/) (multiplication de requêtes),
  [C-ECO-02](./C-ECO-02/) (multiplication d'opérations).
- **Limite** : le rate-limiting des verbes de **lecture** (`GET`/`HAS`/`PROBE`) est **TODO**.

## 1.9 Bornage réseau : ConnectionGater / ResourceManager / ConnManager — P11

`internal/net/defense.go` (`DefenseConfig`, câblé via `HostConfig.Defense`) : le
`ResourceManager` et le `ConnManager` libp2p bornent connexions et ressources
(`-conn-low`/`-conn-high`/`-conn-grace`) ; le `ConnectionGater` applique une blocklist par
pair / sous-réseau (`LoadBlocklistFile`/`ParseBlocklist`), alimentée statiquement et par le
détecteur d'abus (§1.6). C'est le plafond de *flux/connexion* (par opposition au plafond de
stockage du ledger).

- **Scénarios couverts** : [N-DISP-07](./N-DISP-07/) (saturation CPU/mémoire/bande passante),
  [N-DISP-03](./N-DISP-03/) (refus de répondre imposé aux pairs indésirables),
  [N-PROTO-02](./N-PROTO-02/) (Eclipse : diversité de connexions + blocklist),
  [C-DISP-02](./C-DISP-02/) (multiplication des connexions).

## 1.10 Découverte DHT privée + transport libp2p authentifié — P15, P17

Découverte Kademlia sur un préfixe privé `/revika` (`internal/net/dht.go`, `Discovery`) : la
localisation d'un shard est un *provider record*, pas un anneau de hash ; un déplacement =
une ré-annonce, et la redondance de la DHT évite le point unique. Le transport libp2p est
**chiffré et authentifié de bout en bout** (identité de pair = clé libp2p), si bien qu'un
pair est authentifié avant tout échange et le trafic est confidentiel en transit.

- **Scénarios couverts** : [N-PROTO-03](./N-PROTO-03/) (redirection vers de faux pairs :
  pairs authentifiés), [N-CONF-04](./N-CONF-04/) (observation des flux : transport chiffré),
  [N-DISP-05](./N-DISP-05/) (partition : découverte redondante),
  [N-AC-05](./N-AC-05/)/[C-AC-03](./C-AC-03/) (falsifier l'identité d'un demandeur : identité
  de pair authentifiée + token signé).

## 1.11 Protocoles versionnés fail-closed — P18

Une seule version par protocole de stream (`ShardProtocol`, `ProbeProtocol`, … dans
`proto.go`) est enregistrée et offerte ; le muxer libp2p **échoue la négociation** contre un
pair non concordant plutôt que de mal cadrer une trame. L'ID de version est bumpé quand la
trame change, sans conserver le prédécesseur (pas de rétro-compat en dev). Les versions
servies sont annoncées au démarrage et sur `/status` + `/metrics` (`internal/net/metrics.go`).

- **Scénarios couverts** : [N-PROTO-05](./N-PROTO-05/) (exploitation de vulnérabilités :
  surface réduite, entrées strictement validées), [N-PROTO-06](./N-PROTO-06/) (désactivation
  de vérifications : le pair non conforme échoue la négociation),
  [C-PROTO-02](./C-PROTO-02/) (ordre invalide), [C-PROTO-03](./C-PROTO-03/) (ancienne version
  du protocole : refusée), [C-PROTO-04](./C-PROTO-04/) (comportements indéfinis).

## 1.12 Principe « nœud bête / non fiable » — P23 (et provenance P26)

Le nœud est conçu pour ne mériter aucune confiance de confidentialité : il ne voit que du
ciphertext auto-vérifiant adressé par CID (§1.1), toute la re-vérification décisive a lieu
côté User (§2). La sécurité **ne dépend pas** du bon comportement du nœud. La chaîne de
build reste pure-Go, sans cgo, toolchain épinglée (`go 1.26`), dépendances vendorées — pour
la provenance (P26).

- **Scénarios couverts** (comme principe d'ingénierie sous-jacent) : l'ensemble des
  `N-CONF-*` et `N-INT-STO-*` (voir §2.1–§2.3 pour les mécanismes client qui les
  neutralisent), [N-PROTO-04](./N-PROTO-04/) (logiciel modifié : un nœud modifié ne gagne
  aucun accès au plaintext ni aux clés).

---

# 2. Défenses côté client

Mécanismes qui s'exécutent côté User (`cmd/revika-ctl`, `internal/crypto`, `internal/cap`,
`internal/manifest`, `internal/device`, `internal/provider`). Ils protègent la
**confidentialité** et l'**intégrité** des données de l'utilisateur *malgré* des nœuds non
fiables, ainsi que le **contrôle d'accès** (partage, révocation, appareils). C'est ici que
sont neutralisés la plupart des scénarios `N-CONF-*` et `N-INT-STO-*` : ils *ciblent* les
nœuds mais sont *défaits* par du code client.

## 2.1 Chiffrement client-side AES-256-GCM — P1

`internal/crypto` (`Key`, `Seal`, `Open`, AES-256-GCM, AEAD, seal non déterministe). **Tout
est chiffré côté client avant que le moindre shard ne quitte la machine** (pipeline
`chunk → compress → encrypt → erasure`, `internal/pipeline`). Un nœud ne stocke que du
ciphertext opaque ; aucune clé n'atteint jamais un nœud.

- **Scénarios couverts** : [N-CONF-01](./N-CONF-01/) (lecture non autorisée des shards),
  [N-CONF-02](./N-CONF-02/)/[N-CONF-03](./N-CONF-03/) (analyse d'accès / corrélation de
  métadonnées — le contenu reste opaque), [C-CONF-01](./C-CONF-01/) (déduire l'existence de
  données — atténué, cf. §2.10).

## 2.2 Encapsulation de capacités ML-KEM-768 — P2

`internal/cap` (`Wrap`/`Unwrap`, ML-KEM-768 en KEM-DEM + AES-256-GCM, PQC) et
`internal/manifest` (`WrapCap`/`UnwrapCap`). Le **partage = encapsulation de clés**, jamais
copie de plaintext : une read-capability (localisation du manifeste + clé de déchiffrement)
est encapsulée vers la pubkey ML-KEM du destinataire. `share rvk:PATH -to <pubkey-file>`
scelle un `RootPointer` ancré au sous-arbre à la clé du destinataire — un *sealed shared
root*, **jamais un jeton porteur**. Les pubkeys sont toujours passées comme **fichiers**,
jamais en clair sur la ligne de commande.

- **Scénarios couverts** : [C-AC-01](./C-AC-01/) (accès sans autorisation : sans la clé
  privée ML-KEM, rien ne se déchiffre), [C-AC-06](./C-AC-06/) (partage de droits : un cap est
  scellé à un destinataire, pas un secret rejouable), [N-CONF-01](./N-CONF-01/) (la clé reste
  côté User).

## 2.3 Re-vérification d'adresse de contenu à la restitution — P5, P19

Au téléchargement, le client re-hache chaque shard (`store.Get` → `ErrCorrupt`), et
`NetStore.putRaw` vérifie que le nœud a bien échoté le CID exact au stockage. La racine
mutable est un `manifest.RootPointer` **signé Ed25519 et versionné** (`SignRoot`, `Seq`
monotone), persisté via `provider.FileRootStore` (`root.json`, **anti-rollback** : refuse un
`Seq` inférieur). Un nœud ne peut donc ni corrompre un shard sans être détecté, ni resservir
une **ancienne** racine sans que le numéro de version ne le trahisse.

- **Scénarios couverts** : [N-INT-STO-01](./N-INT-STO-01/) (altération détectée),
  [N-INT-STO-02](./N-INT-STO-02/) (corruption détectée + décodage à partir des sains),
  [N-INT-STO-03](./N-INT-STO-03/) (rollback : `Seq` monotone + anti-rollback local),
  [C-INT-DAT-01](./C-INT-DAT-01/) (données corrompues rejetées),
  [C-INT-MET-04](./C-INT-MET-04/) (manipulation des versions),
  [N-INT-MET-02](./N-INT-MET-02/) (les timestamps ne sont pas de confiance : l'ordre est
  porté par `Seq` signé).

## 2.4 Placement réparti sur owners indépendants + décodage tolérant — P6, P16

`internal/placement` (`Selector` round-robin / weighted, `Spread` par domaine de défaillance)
répartit les shards d'une stripe sur des nœuds/pubkeys **distincts** : aucun sous-ensemble
< `k` ne reconstitue le fichier, et n'importe quels `k` sur `k+m` suffisent au décodage
(`erasure.Decode`). Le client tolère donc un nœud qui retient, corrompt ou disparaît, tant
que `k` shards sains restent joignables.

- **Scénarios couverts** : [N-DISP-01](./N-DISP-01/)/[N-DISP-02](./N-DISP-02/)/[N-DISP-03](./N-DISP-03/)
  (suppression / refus de fournir / refus de répondre : décodage depuis les autres),
  [N-CONF-01](./N-CONF-01/) (confidentialité par fragmentation : un nœud ne détient jamais un
  fichier entier), [N-ORG-SYB-04](./N-ORG-SYB-04/)/[N-ORG-GEO-03](./N-ORG-GEO-03/)
  (concentration : le spread par domaine de défaillance la contre — voir limites §5).

## 2.5 Identité de signature Ed25519 auto-certifiante — P3, P9

`internal/cap` (`SignKey`/`SignPubKey`, `MintSigningKey`, `MeetsPoW`). L'identité de
propriétaire de stockage est une clé Ed25519 **broyée par PoW** (`-pow-difficulty`, défaut
12) : sa pubkey hache sous une cible, donc re-miner une identité coûte du CPU. Tous les
jetons et capacités sont signés Ed25519 ; toute signature invalide est rejetée, la forge
exigeant la clé privée.

- **Scénarios couverts** : [C-AC-03](./C-AC-03/) (jeton falsifié rejeté),
  [C-INT-SIG-02](./C-INT-SIG-02/) (signature d'un contenu différent : la signature couvre le
  contenu), [N-INT-ID-01](./N-INT-ID-01/) (usurpation d'identité),
  [N-AC-05](./N-AC-05/) (falsifier l'identité d'un demandeur),
  [C-INT-MET-03](./C-INT-MET-03/) (fausse origine : l'origine est la pubkey signataire).

## 2.6 Anti-rejeu : nonce, TTL, seq — P8

Nonce frais à usage unique dans les défis de possession (`NonceSize=32`, §1.4), `Seq`
monotone signé sur les racines (§2.3), baux TTL côté ledger (§1.5). Une réponse, une racine
ou un droit ne peuvent être **rejoués** hors de leur fenêtre.

- **Scénarios couverts** : [C-INT-SIG-03](./C-INT-SIG-03/) (rejeu de signature),
  [N-INT-PRE-02](./N-INT-PRE-02/) (réutilisation d'anciennes preuves),
  [N-INT-REG-05](./N-INT-REG-05/) (rejeu d'événements — pour la partie couverte par `Seq`),
  [C-AC-02](./C-AC-02/) (réutilisation d'un droit expiré, via TTL).

## 2.7 Capacités révocables : re-keying forward — P12

`revoke rvk:PATH` (`manifest.Rekey`) re-clé le sous-arbre jusqu'à ses data chunks, avance +
republie la racine, et réclame les shards orphelins : une capacité partagée antérieurement
**ne peut plus lire les octets courants** (révocation *forward-only* — les copies déjà
téléchargées ne sont pas rattrapables). C'est une révocation par re-chiffrement, pas par
autorisation côté nœud.

- **Scénarios couverts** : [C-AC-05](./C-AC-05/) (contournement de révocation : les nouveaux
  octets sont sous une nouvelle clé), [N-AC-01](./N-AC-01/) (ignorer une révocation : le nœud
  n'a rien à appliquer — la révocation est cryptographique),
  [N-AC-03](./N-AC-03/)/[N-AC-04](./N-AC-04/) (servir après expiration / permissions
  obsolètes : sans re-key, un cap révoqué ne déchiffre plus).
- **Limite** : la révocation d'**écriture** appliquée par le nœud est **différée** ; seule la
  révocation de lecture est cryptographiquement forcée.

## 2.8 Modèle d'appareils révocables sous credential maître — P3, P12

`internal/device` (`Auth` = ensemble signé par la clé maître des pubkeys ML-KEM d'appareils,
`devices.json`, miroir DHT `/revika-devices/<owner>`). Le User est un *principal* dont le
**credential maître** (clé Ed25519 owner, hors ligne) enrôle/révoque des *appareils*
individuellement clés. `device revoke` avance l'ensemble signé et **rescelle le companion de
racine à exactement les appareils survivants** (`manifest.SealFullRootFor` →
`FullRootRecord.Seals`) : la clé d'un appareil révoqué n'ouvre plus aucun companion courant
(`manifest.ErrNoSealForKey`).

- **Scénarios couverts** : [C-INT-SIG-04](./C-INT-SIG-04/) (signature volée / appareil
  compromis : révocable), [C-INT-SIG-05](./C-INT-SIG-05/) (clé compromise),
  [C-AC-04](./C-AC-04/) (escalade de privilèges : l'ensemble d'appareils est signé par le
  maître hors ligne), [N-INT-ID-03](./N-INT-ID-03/) (vol de clé d'appareil, périmètre borné).
- **Limite** : révocation de lecture forward-only (plaintext déjà téléchargé non rattrapable).

## 2.9 Commit multi-appareils : merge-publish sans perte — P7 (partiel), P19

`commitRoot` (`cmd/revika-ctl`) est une boucle **read-merge-publish** : chaque commit lit la
racine DHT courante, la compare à la base de merge (le `root.json` local durable), fait un
merge à trois voies (`manifest.Merge3`) si divergence — les feuilles conflictuelles
deviennent des **copies de conflit taggées par appareil** (`Config.DeviceTag`), jamais des
pertes silencieuses — signe à `max(local,remote).Seq+1`, et re-lit pour rattraper un writer
concurrent. `rootValidator.Select` casse un fork à `Seq` égal par ordre d'octets total (pas
premier-vu), pour que les répliques **convergent**. La racine déchiffrable atteint les autres
appareils via le *sealed self-root companion* (`manifest.FullRootRecord`, DHT
`/revika-fullcap/<owner>`), la racine publique restant dépouillée de clé.

- **Scénarios couverts** : [C-INT-DAT-03](./C-INT-DAT-03/) (versions incompatibles :
  réconciliées, pas perdues), [N-INT-REG-01](./N-INT-REG-01/) (double publication : `Select`
  déterministe converge), [C-COL-04](./C-COL-04/)/[N-INT-REG-04](./N-INT-REG-04/) (faux
  événements coordonnés : seules les racines signées par l'owner sont retenues).
- **Limite** : ce n'est pas un journal distribué corroboré (P27, P7 complet) — voir §5.

## 2.10 Normalisation : chunking taille fixe + isolation des clés — P25, P24

Chunking à taille fixe (`internal/chunk`) et compression per-chunk seulement si elle gagne
(`internal/compress`) : les shards sont **normalisés**, ce qui limite l'analyse de
corrélation par taille. Les clés User (ML-KEM + Ed25519 signature) vivent uniquement sous
`.revika/keys` (git-ignored), **jamais transmises hors machine**, avec permissions
restreintes (P24).

- **Scénarios couverts** : [N-CONF-03](./N-CONF-03/)/[N-CONF-05](./N-CONF-05/) (corrélation
  de métadonnées / inférence de relations : atténuées par normalisation),
  [C-CONF-01](./C-CONF-01/) (déduction d'existence : atténuée),
  [N-INT-ID-03](./N-INT-ID-03/)/[C-INT-SIG-04](./C-INT-SIG-04/) (vol de clé : isolation
  réduit la surface).
- **Limite** : le chunking à taille fixe (CDC prévu) et la normalisation n'éliminent pas
  l'analyse de trafic fine ; l'observation de temps de réponse ([C-CONF-03](./C-CONF-03/),
  [N-CONF-02](./N-CONF-02/)) reste partiellement exposée.

## 2.11 Inspection verify-only d'une racine publiée — P19

`ls -owner <pubkey-file>` résout la racine DHT publiée d'un namespace **uniquement sous sa
forme verify-cap** (localisation des shards + intégrité, **aucun déchiffrement**) : c'est un
inspecteur de liveness/révocation, pas un chemin de navigation. La racine publique reste
dépouillée de clé (§2.9). Aucune clé de lecture n'est exposée par cette voie.

- **Scénarios couverts** : [C-AC-01](./C-AC-01/) (inspecter sans lire),
  [N-CONF-01](./N-CONF-01/) (la voie publique ne divulgue pas de clé).

---

# 3. Défenses partagées (nœud ⇄ client)

- **Transport libp2p chiffré/authentifié — P17** (§1.10) : protège tout échange dans les deux
  sens ([N-CONF-04](./N-CONF-04/), [C-CONF-02](./C-CONF-02/)).
- **Grants signés — P20** (§1.7) : émis côté client, vérifiés côté nœud.
- **Adressage par contenu — P4/P5** (§1.1, §2.3) : self-vérification aux deux extrémités.

---

# 4. Couverture et angles morts

Correspondance synthétique scénario → défense principale. `✔` implémenté, `~` partiel/atténué,
`✗` différé (voir §5).

## 4.1 Scénarios ciblant les nœuds

| Scénario | Défense principale | Statut |
| --- | --- | --- |
| [N-CONF-01](./N-CONF-01/) Lecture shards | P1 chiffrement + P6/P16 fragmentation (§2.1, §2.4) | ✔ |
| [N-CONF-02](./N-CONF-02/) Analyse des accès | P25 normalisation (§2.10) | ~ |
| [N-CONF-03](./N-CONF-03/) Corrélation métadonnées | P1 + P25 (§2.1, §2.10) | ~ |
| [N-CONF-04](./N-CONF-04/) Observation flux | P17 transport chiffré (§1.10) | ✔ |
| [N-CONF-05](./N-CONF-05/) Inférence relations | P25 normalisation (§2.10) | ~ |
| [N-INT-STO-01](./N-INT-STO-01/) Altération shard | P4/P5 (§1.1, §2.3) | ✔ |
| [N-INT-STO-02](./N-INT-STO-02/) Shard corrompu | P5 + P6 décodage (§2.3, §1.3) | ✔ |
| [N-INT-STO-03](./N-INT-STO-03/) Rollback | P19 `Seq` + anti-rollback (§2.3) | ✔ |
| [N-INT-STO-04](./N-INT-STO-04/) Réorg locale | P4 adressage contenu (§1.1) | ✔ |
| [N-INT-MET-01](./N-INT-MET-01/) Falsif. métadonnées | P21 descripteur signé (§1.7) | ✔ |
| [N-INT-MET-02](./N-INT-MET-02/) Timestamps | P19 `Seq` signé remplace l'horloge (§2.3) | ✔ |
| [N-INT-MET-03](./N-INT-MET-03/) Réécriture historique | P7/P27 journal corroboré | ✗ |
| [N-INT-MET-04](./N-INT-MET-04/) Suppr. événements | P27 corroboration inter-pairs | ✗ |
| [N-INT-REG-01](./N-INT-REG-01/) Double publication | P19 `Select` déterministe (§2.9) | ✔ |
| [N-INT-REG-02..03](./N-INT-REG-02/) Réécriture/omission registre | P7/P27 | ✗ |
| [N-INT-REG-04](./N-INT-REG-04/) Événements fictifs | P3 signatures (§2.9) | ~ |
| [N-INT-REG-05](./N-INT-REG-05/) Rejeu événements | P8 (§2.6) | ~ |
| [N-INT-PRE-01](./N-INT-PRE-01/) Fausses preuves stockage | P14 + repair-verify (§1.4) | ✔ |
| [N-INT-PRE-02](./N-INT-PRE-02/) Réutilisation preuves | P8 nonce frais (§1.4, §2.6) | ✔ |
| [N-INT-PRE-03](./N-INT-PRE-03/) Mutualisation preuves | P14 défi par-shard | ~ |
| [N-INT-PRE-04](./N-INT-PRE-04/) Preuve sans données | P14 proof-of-retrieval (§1.4) | ✔ |
| [N-INT-PRE-05](./N-INT-PRE-05/) Fausse disponibilité | P14 (§1.4) | ✔ |
| [N-INT-ID-01](./N-INT-ID-01/) Usurpation | P3/P9 identité auto-certif. (§2.5) | ✔ |
| [N-INT-ID-02](./N-INT-ID-02/) Duplication identité | P9 PoW (§1.2, §2.5) | ~ |
| [N-INT-ID-03](./N-INT-ID-03/) Vol clé privée | P24 isolation + P12 révocation (§2.8, §2.10) | ~ |
| [N-DISP-01](./N-DISP-01/) Suppr. shard | P6 réparation + GUARD2 (§1.3) | ✔ |
| [N-DISP-02..03](./N-DISP-02/) Refus fournir/répondre | P6/P16 décodage ailleurs (§2.4) | ✔ |
| [N-DISP-04](./N-DISP-04/) Ralentissement | P10 + AbuseMonitor (§1.6, §1.8) | ~ |
| [N-DISP-05](./N-DISP-05/) Partition | P15 DHT + P6 (§1.10, §1.3) | ~ |
| [N-DISP-06](./N-DISP-06/) Blocage gossip | s/o (revika = DHT, pas de gossip) | ~ |
| [N-DISP-07](./N-DISP-07/) Saturation | P9/P10/P11/P13 (§1.2, §1.8, §1.9, §1.5) | ✔ |
| [N-DISP-08](./N-DISP-08/) Refus maintenance | P14 + AbuseMonitor (§1.4, §1.6) | ✔ |
| [N-DISP-09](./N-DISP-09/) Déconnexion stratégique | P6 réparation + P14 (§1.3, §1.4) | ~ |
| [N-AC-01](./N-AC-01/) Ignorer révocation | P12 re-key cryptographique (§2.7) | ✔ |
| [N-AC-02](./N-AC-02/) Accès sans autorisation | P20 grant signé (§1.7) | ✔ |
| [N-AC-03..04](./N-AC-03/) Après expiration / obsolète | P12 + P8 TTL (§2.7, §2.6) | ~ |
| [N-AC-05](./N-AC-05/) Falsifier demandeur | P3 + P17 pair authentifié (§2.5, §1.10) | ✔ |
| [N-PROTO-01](./N-PROTO-01/) Faux Gossip | s/o (DHT ; injection = record signé requis) | ~ |
| [N-PROTO-02](./N-PROTO-02/) Eclipse | P11 + P15 diversité (§1.9, §1.10) | ~ |
| [N-PROTO-03](./N-PROTO-03/) Faux pairs | P17 authentif. (§1.10) | ✔ |
| [N-PROTO-04](./N-PROTO-04/) Logiciel modifié | P23 nœud non fiable (§1.12) | ✔ |
| [N-PROTO-05](./N-PROTO-05/) Vulnérabilités | P18 fail-closed (§1.11) | ~ |
| [N-PROTO-06](./N-PROTO-06/) Désactivation vérifs | P18 + P23 re-vérif. User (§1.11, §1.12) | ✔ |
| [N-ECO-01..04](./N-ECO-01/) Menaces économiques | couche incitative | ✗ |
| [N-ORG-SYB-01](./N-ORG-SYB-01/) Faux nœuds | P9 PoW (§1.2) | ~ |
| [N-ORG-SYB-02](./N-ORG-SYB-02/) Collusion nœuds | P16/GUARD2 concentration (§1.3, §2.4) | ~ |
| [N-ORG-SYB-03..04](./N-ORG-SYB-03/) Censure/majorité régionale | anti-Sybil + réputation | ✗ |
| [N-ORG-GEO-01..04](./N-ORG-GEO-01/) Géolocalisation | P22 diversité mesurée (partiel) | ✗ |

## 4.2 Scénarios ciblant les clients

| Scénario | Défense principale | Statut |
| --- | --- | --- |
| [C-CONF-01](./C-CONF-01/) Existence de données | P1 + P25 (§2.1, §2.10) | ~ |
| [C-CONF-02](./C-CONF-02/) Corrélation métadonnées | P17 + P25 (§1.10, §2.10) | ~ |
| [C-CONF-03](./C-CONF-03/) Temps de réponse | — | ✗ |
| [C-CONF-04](./C-CONF-04/) Infos publiques | P19 verify-only cap (§2.11) | ~ |
| [C-INT-DAT-01](./C-INT-DAT-01/) Données corrompues | P5 re-vérif. (§2.3) | ✔ |
| [C-INT-DAT-02](./C-INT-DAT-02/) Modif. non autorisée | P3/P19 racine signée (§2.3, §2.5) | ✔ |
| [C-INT-DAT-03](./C-INT-DAT-03/) Versions incompatibles | P19 merge3 (§2.9) | ✔ |
| [C-INT-DAT-04](./C-INT-DAT-04/) Suppression logique | P19 `Seq` + P6 réparation | ~ |
| [C-INT-DAT-05](./C-INT-DAT-05/) Injection malveillante | P3 signature owner (§2.5) | ✔ |
| [C-INT-MET-01](./C-INT-MET-01/) Falsification | P19 manifeste signé (§2.3) | ✔ |
| [C-INT-MET-02](./C-INT-MET-02/) Timestamps | P19 `Seq` (§2.3) | ✔ |
| [C-INT-MET-03](./C-INT-MET-03/) Fausse origine | P3 pubkey signataire (§2.5) | ✔ |
| [C-INT-MET-04](./C-INT-MET-04/) Manip. versions | P19 anti-rollback (§2.3) | ✔ |
| [C-INT-MET-05](./C-INT-MET-05/) Fausse liste destinataires | P2 seals par appareil (§2.2, §2.8) | ✔ |
| [C-INT-SIG-01](./C-INT-SIG-01/) Double signature | P3 + P19 `Select` (§2.9) | ~ |
| [C-INT-SIG-02](./C-INT-SIG-02/) Contenu différent | P3 (§2.5) | ✔ |
| [C-INT-SIG-03](./C-INT-SIG-03/) Rejeu | P8 (§2.6) | ✔ |
| [C-INT-SIG-04](./C-INT-SIG-04/) Signature volée | P12 révocation appareil (§2.8) | ✔ |
| [C-INT-SIG-05](./C-INT-SIG-05/) Clé compromise | P12 révocation (§2.8) | ✔ |
| [C-INT-JRN-01..04](./C-INT-JRN-01/) Journaux | P7/P27 journal corroboré | ✗ |
| [C-DISP-01](./C-DISP-01/) Flood | P10 (§1.8) | ✔ |
| [C-DISP-02](./C-DISP-02/) Multiplication connexions | P11 (§1.9) | ✔ |
| [C-DISP-03](./C-DISP-03/) Téléch. interrompus | P6 idempotent + P4 (§1.3) | ~ |
| [C-DISP-04](./C-DISP-04/) Reconstructions massives | P13 quotas (§1.5) | ~ |
| [C-DISP-05](./C-DISP-05/) Saturation vérifs | P10/P11 (§1.8, §1.9) | ~ |
| [C-AC-01](./C-AC-01/) Accès sans autorisation | P2 cap scellé (§2.2) | ✔ |
| [C-AC-02](./C-AC-02/) Droit expiré | P8 TTL (§2.6) | ~ |
| [C-AC-03](./C-AC-03/) Jeton falsifié | P3 (§2.5) | ✔ |
| [C-AC-04](./C-AC-04/) Escalade privilèges | P3/P12 credential maître (§2.8) | ✔ |
| [C-AC-05](./C-AC-05/) Contournement révocation | P12 re-key (§2.7) | ✔ |
| [C-AC-06](./C-AC-06/) Partage de droits | P2 cap non porteur (§2.2) | ~ |
| [C-PROTO-01..04](./C-PROTO-01/) Protocolaires | P18 fail-closed (§1.11) | ✔ |
| [C-PROTO-05](./C-PROTO-05/) Fausses capacités | P14 sondes (§1.4) | ~ |
| [C-ECO-01](./C-ECO-01/) Création massive | P9 + P13 (§1.2, §1.5) | ~ |
| [C-ECO-02](./C-ECO-02/) Multiplication opérations | P10 (§1.8) | ~ |
| [C-ECO-03](./C-ECO-03/) Cycles create/delete | P13 baux/quotas (§1.5) | ~ |
| [C-ECO-04](./C-ECO-04/) Ressources gratuites | P9 PoW (§1.2) | ~ |
| [C-COL-01..02](./C-COL-01/) Collusion clients/nœuds | P16 + réputation | ~ |
| [C-COL-03](./C-COL-03/) Partage de clés | P12 révocation (§2.7, §2.8) | ~ |
| [C-COL-04](./C-COL-04/) Faux événements coordonnés | P3/P19 (§2.9) | ~ |

---

# 5. Angles morts assumés (différés)

Cohérent avec Architecture.md §5 et [`frameworks.md`](./frameworks.md#angles-morts-assumés) :

- **Journal distribué corroboré (P7 complet, P27)** — le ledger revika est par-nœud, local
  SQLite ; il n'y a pas de journal append-only répliqué et corroboré entre pairs. Les
  scénarios de réécriture/omission d'historique et d'audit
  ([N-INT-MET-03/04](./N-INT-MET-03/), [N-INT-REG-02/03](./N-INT-REG-02/),
  [C-INT-JRN-01..04](./C-INT-JRN-01/)) restent **non couverts**.
- **Anti-Sybil global, réputation, incitations économiques** — le PoW renchérit la création
  d'identités mais ne l'élimine pas ; il n'existe pas de couche de réputation ni de paiement.
  [N-ECO-*](./N-ECO-01/), [C-ECO-*](./C-ECO-01/), [N-ORG-SYB-03/04](./N-ORG-SYB-03/),
  [C-COL-01/02](./C-COL-01/) restent **partiels ou différés**.
- **Géolocalisation vérifiable (P22)** — la diversité de placement mesurée par le réseau
  (RTT/AS observés) est prévue mais pas contraignante ; [N-ORG-GEO-*](./N-ORG-GEO-01/) est
  **différé**. Le `geoip` actuel (`internal/geoip`) sert la carte du dashboard `/nodes`, pas
  une preuve de localisation.
- **Rate-limiting des lectures** — `GET`/`HAS`/`PROBE` ne sont pas encore plafonnés ;
  [C-DISP-05](./C-DISP-05/), [C-CONF-03](./C-CONF-03/) restent partiellement exposés.
- **Révocation d'écriture appliquée par le nœud** — seule la révocation de **lecture** est
  cryptographiquement forcée (re-key, §2.7) ; la révocation d'écriture côté nœud est différée.
- **Révocation de grant** — l'expiration `0` = jamais ; la révocation de grant est **TODO**
  (`internal/stripe`).
- **Pas de couche gossip** — revika découvre via DHT ; les scénarios formulés en termes de
  gossip ([N-PROTO-01](./N-PROTO-01/), [N-DISP-06](./N-DISP-06/)) sont ré-interprétés sur la
  DHT (un record doit être signé pour être retenu ; bloquer la propagation revient à une
  partition, atténuée par la redondance DHT).

---

## Voir aussi

- [`Security.md`](./Security.md) — catalogue des scénarios d'attaque (source des IDs).
- [`README.md`](./README.md) — index des fiches par scénario.
- [`frameworks.md`](./frameworks.md) — catalogue des primitives P1–P27 et mappings D3FEND / NIST.
- [`../Architecture.md`](../Architecture.md) — conception détaillée et couches différées (§5).
- [`../CLAUDE.md`](../CLAUDE.md) — principes directeurs et contraintes de conception.
