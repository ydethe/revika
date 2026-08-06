Run the seed node — the only node that states the PoW policy :

     go run ./cmd/revika-node -data=./.revika -listen=/ip4/127.0.0.1/tcp/4002 -pow-difficulty 2 -pow-puzzle argon2id

Add a second node that only *joins* : it passes -bootstrap and no -pow flags, so
it reads the seed's PoW policy over /revika/params and enforces the same bar (a
joining node inherits admission; only the seed configures it) :

     go run ./cmd/revika-node -data=./.revika-n2 -listen=/ip4/127.0.0.1/tcp/4003 -bootstrap /ip4/127.0.0.1/tcp/4002/p2p/xxxxxx

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
