Run the node :

     go run ./cmd/revika-node -data=./.revika -listen=/ip4/127.0.0.1/tcp/4001 -pow-difficulty 2 -pow-puzzle argon2id

Connect to it — create a workspace folder holding config.json (bootstrap peer,
erasure k/m, PoW policy), where root.json and your keys will also live :

     go run ./cmd/revika-ctl connect -root ws -label "local node" -pow-difficulty 2 -pow-puzzle argon2id /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx

Store a directory into your namespace (advances ws/root.json). No -bootstrap
needed — it comes from ws/config.json; the first write mints your identity into
ws/keys after a confirmation prompt :

     go run ./cmd/revika-ctl cp -root ws /path/to/your/root/folder rvk:folder

Browse it (reads directory blobs only, no file content) :

     go run ./cmd/revika-ctl ls -root ws -l rvk:folder

Give the guest their own workspace and identity :

     go run ./cmd/revika-ctl connect -root guest -pow-difficulty 2 -pow-puzzle argon2id /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx
     go run ./cmd/revika-ctl keygen -key guest/keys/user -pow-difficulty 2 -pow-puzzle argon2id

Share a single file (seals a shared root to the recipient's key — no bearer token) :

     go run ./cmd/revika-ctl share -root ws -to @guest/keys/user.pub -o share.root.json rvk:folder/testfile.bin

Retrieve a shared file (the recipient opens the sealed root file with their key;
-root here names a file, so it is a bare root pointer, not a workspace) :

     go run ./cmd/revika-ctl cp -root share.root.json -key guest/keys/user.key -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx rvk: ./testfile.bin

Share a whole subtree instead — point `share` at a directory, then browse/retrieve it :

     go run ./cmd/revika-ctl share -root ws -to @guest/keys/user.pub -o shared-dir.root.json rvk:folder
     go run ./cmd/revika-ctl ls -root shared-dir.root.json -key guest/keys/user.key -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx rvk:
     go run ./cmd/revika-ctl cp -root shared-dir.root.json -key guest/keys/user.key -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx rvk: .guest_test
