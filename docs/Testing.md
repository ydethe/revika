Run the node :

     go run ./cmd/revika-node -data=./.revika -listen=/ip4/127.0.0.1/tcp/4001 -pow-difficulty 2 -pow-puzzle argon2id

Connect to it — create a workspace folder holding config.json (bootstrap peer,
erasure k/m, PoW policy), where root.json and your keys will also live. `connect`
reads the node's PoW policy over the wire (no -pow flags) and mints your identity
in place, grinding to that difficulty :

     go run ./cmd/revika-ctl connect -root ws -label "local node" /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx

Store a directory into your namespace (advances ws/root.json). No -bootstrap
needed — it comes from ws/config.json; connect already minted your identity into
ws/keys :

     go run ./cmd/revika-ctl cp -root ws /path/to/your/root/folder rvk:folder

Browse it (reads directory blobs only, no file content) :

     go run ./cmd/revika-ctl ls -root ws -l rvk:folder

Give the guest their own workspace and identity (connect mints it, reading the
node's PoW policy over the wire) :

     go run ./cmd/revika-ctl connect -root guest /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx

Share a single file (seals a shared root to the recipient's key — no bearer token) :

     go run ./cmd/revika-ctl share -root ws -to @guest/keys/user.pub -o share.root.json rvk:folder/testfile.bin

Share a whole subtree instead — point `share` at a directory, then browse/retrieve it :

     go run ./cmd/revika-ctl share -root ws -to @guest/keys/user.pub -o shared-dir.root.json rvk:folder
     go run ./cmd/revika-ctl ls -root shared-dir.root.json -key guest/keys/user.key -node /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx rvk:
     go run ./cmd/revika-ctl cp -root shared-dir.root.json -key guest/keys/user.key -node /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx rvk: .guest_test
