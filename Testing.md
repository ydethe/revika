Run the node :

     go run ./cmd/revika-node -data=./.revika -listen=/ip4/127.0.0.1/tcp/4001 -pow-difficulty 2 -pow-puzzle argon2id

Create an identity :

     go run ./cmd/revika-ctl keygen -key user  -pow-difficulty 2 -pow-puzzle argon2id
     go run ./cmd/revika-ctl keygen -key guest -pow-difficulty 2 -pow-puzzle argon2id
     
Put a directory :

     go run ./cmd/revika-ctl put -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx -signkey user.sign.key -r /path/to/your/root/folder

Share a single file  :

     go run ./cmd/revika-ctl share -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx -manifest .test.rvk.json -path "testfile.bin" -to @guest.pub -o share.cap

Retrieve a shared file :

     go run ./cmd/revika-ctl get -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx -cap share.cap -key @guest.key
     
For a directory that has been shared in a share.cap, you can sync (without downloading the content) :

     go run ./cmd/revika-ctl sync -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx -cap share.cap -key guest.key -o .guest_test

Then hydrate files :
     
     go run ./cmd/revika-ctl hydrate -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx .guest_test/testfile.bin
