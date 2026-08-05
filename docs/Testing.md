Run the node :

     go run ./cmd/revika-node -data=./.revika -listen=/ip4/127.0.0.1/tcp/4001 -pow-difficulty 2 -pow-puzzle argon2id

Create an identity :

     go run ./cmd/revika-ctl keygen -key user  -pow-difficulty 2 -pow-puzzle argon2id
     go run ./cmd/revika-ctl keygen -key guest -pow-difficulty 2 -pow-puzzle argon2id

Store a directory into your namespace (advances .revika/root.json) :

     go run ./cmd/revika-ctl cp -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx -signkey user.sign.key /path/to/your/root/folder rvk:folder

Browse it (reads directory blobs only, no file content) :

     go run ./cmd/revika-ctl ls -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx -l rvk:folder

Share a single file (seals a shared root to the recipient's key — no bearer token) :

     go run ./cmd/revika-ctl share -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx -signkey user.sign.key -to @guest.pub -o share.root.json rvk:folder/testfile.bin

Retrieve a shared file (the recipient opens the sealed root with their key) :

     go run ./cmd/revika-ctl cp -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx -root share.root.json -key guest.key rvk: ./testfile.bin

Share a whole subtree instead — point `share` at a directory, then browse/retrieve it :

     go run ./cmd/revika-ctl share -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx -signkey user.sign.key -to @guest.pub -o shared-dir.root.json rvk:folder
     go run ./cmd/revika-ctl ls -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx -root shared-dir.root.json -key guest.key rvk:
     go run ./cmd/revika-ctl cp -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx -root shared-dir.root.json -key guest.key rvk: .guest_test
