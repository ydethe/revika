Run the seed node — the only node that states the cluster policy. A node's role is
decided purely by whether -bootstrap is given: the seed (no -bootstrap) declares
admission (PoW) *and* maintenance cadence (repair / rebalance) from its own flags :

     go run ./cmd/revika-node -data=./.revika -listen=/ip4/127.0.0.1/tcp/4002 -pow-difficulty 2 -repair-interval 30s -rebalance-interval 30s

Add a second node that only *joins* : it passes -bootstrap and no policy flags, so
it reads the seed's whole policy over /revika/params (net.FetchNodePolicy) and
enforces the same bar — admission *and* the repair/rebalance schedule (a joining
node inherits the cluster policy; only the seed configures it) :

     go run ./cmd/revika-node -data=./.revika-n2 -listen=/ip4/127.0.0.1/tcp/4003 -bootstrap /ip4/127.0.0.1/tcp/4002/p2p/xxxxxx

Any policy flags a joining node also passes are ignored with a warning (the cluster
policy governs). The one exception is the *local* maintenance-abuse defence, always
honored per node: -rebalance-abuse-tolerance/-coalesce/-strikes/-decay tune when a
peer that rebalances against this node off-schedule, or repeatedly fails a
possession probe, is added to this node's persistent blocklist (-blocklist-auto,
default <data>/blocklist.auto). Watch for a `defense.blacklist` log line :

     go run ./cmd/revika-node -data=./.revika-n3 -listen=/ip4/127.0.0.1/tcp/4004 -bootstrap /ip4/127.0.0.1/tcp/4002/p2p/xxxxxx -rebalance-abuse-strikes 2

Connect to it — create a workspace folder holding config.json (bootstrap peer,
erasure k/m, PoW policy), where root.json and your keys will also live. `connect`
reads the node's PoW policy over the wire (no -pow flags) and mints your identity
in place, grinding to that difficulty :

     go run ./cmd/revika-ctl connect -root ws -label "local node" /ip4/127.0.0.1/tcp/4002/p2p/xxxxxx

Store a directory into your namespace (advances ws/root.json). No -bootstrap
needed — it comes from ws/config.json; connect already minted your identity into
ws/keys :

     go run ./cmd/revika-ctl cp -root ws /path/to/your/root/folder rvk:folder

Browse it (reads directory blobs only, no file content) :

     go run ./cmd/revika-ctl ls -root ws -l rvk:folder

Give the guest their own workspace and identity (connect mints it, reading the
node's PoW policy over the wire) :

     go run ./cmd/revika-ctl connect -root guest /ip4/127.0.0.1/tcp/4002/p2p/xxxxxx

Share a single file (seals a shared root to the recipient's key — no bearer token) :

     go run ./cmd/revika-ctl share -root ws -to guest/keys/user.pub -o share.root.json rvk:folder/testfile.bin

Share a whole subtree instead — point `share` at a directory, then browse/retrieve it :

     go run ./cmd/revika-ctl share -root ws -to guest/keys/user.pub -o shared-dir.root.json rvk:folder
     go run ./cmd/revika-ctl ls -root shared-dir.root.json -key guest/keys/user.key -node /ip4/127.0.0.1/tcp/4002/p2p/xxxxxx rvk:
     go run ./cmd/revika-ctl cp -root shared-dir.root.json -key guest/keys/user.key -node /ip4/127.0.0.1/tcp/4002/p2p/xxxxxx rvk: .guest_test

Resolve the published root pointer over the DHT. Every cp/rm/revoke commit also
publishes your signed root (keyed by your Ed25519 signing pubkey) to the DHT,
behind the durable local ws/root.json. Any client — even one that has never seen
your namespace — resolves it by owner pubkey. The DHT record is a *verify
projection* (shard IDs + seq + k/m, no decryption key), so this reports liveness
and the current sequence, not file contents. `-owner` reads the signing pubkey
from a file (never a literal); point it at ws/keys/user.sign.pub :

     go run ./cmd/revika-ctl ls -root guest -owner ws/keys/user.sign.pub

Revoke a previously-shared subtree. `revoke` re-encrypts the subtree under fresh
keys down to its data chunks, advances + republishes the signed root (the DHT seq
you just resolved will step up), and reclaims the now-orphaned old shards — so the
recipient's sealed share above can no longer read the current bytes (future reads
only; already-downloaded copies can't be clawed back) :

     go run ./cmd/revika-ctl revoke -root ws rvk:folder

Confirm the published seq advanced, and that the guest's sealed root now fails to
retrieve the revoked subtree (its old shard IDs were reclaimed) :

     go run ./cmd/revika-ctl ls -root guest -owner ws/keys/user.sign.pub
     go run ./cmd/revika-ctl cp -root shared-dir.root.json -key guest/keys/user.key -node /ip4/127.0.0.1/tcp/4002/p2p/xxxxxx rvk: .guest_revoked   # expected to fail

Manage the User's *devices* under the offline master credential (Architecture
§3.7.2). The master credential is the owner Ed25519 signing key (ws/keys/user.sign.key);
a device is one ML-KEM keypair authorized to open the sealed self-root companion.
Bootstrap the device-authorization record (ws/devices.json) with this workspace as
its first member — signed by the master key, mirrored to the DHT :

     go run ./cmd/revika-ctl device init -root ws -label "laptop"

Inspect the record and this device's identity :

     go run ./cmd/revika-ctl device list -root ws
     go run ./cmd/revika-ctl device id -root ws

Bring up a second device. On the real second machine it would share the master
signing key so it can also write; enrollment itself only needs the device's ML-KEM
public key, so here a bare keygen stands in for that machine's ML-KEM keypair
(dev2/user.key/.pub) :

     go run ./cmd/revika-ctl keygen -key dev2/user -pow-difficulty 0

Enroll it from the first device (the master credential). This advances the record,
reseals the self-root companion to {laptop, phone}, and republishes — so the new
device's ML-KEM key can open the current root. `enroll` reads the pubkey from a file
(never a literal) and needs the DHT backend (it comes from ws/config.json) :

     go run ./cmd/revika-ctl device enroll -root ws -label "phone" dev2/user.pub
     go run ./cmd/revika-ctl device list -root ws

Read-revoke that device. Grab its device-id from `device id` (or the `device list`
prefix), then `revoke` advances the record, reseals the companion to the *surviving*
device set only, and advances the root — so the revoked device's key can no longer
open the current root (forward-only: bytes it already downloaded stay with it) :

     DEV2_ID=$(go run ./cmd/revika-ctl device id -root dev2 | awk '/device id:/ {print $3}')
     go run ./cmd/revika-ctl device revoke -root ws "$DEV2_ID"
     go run ./cmd/revika-ctl device list -root ws
