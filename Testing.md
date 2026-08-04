Run the node :

     go run ./cmd/revika-node -data=./.revika -listen=/ip4/127.0.0.1/tcp/4001 -pow-difficulty 12 -pow-puzzle argon2id

Create an identity :

     go run ./cmd/revika-ctl keygen -key user -pow-difficulty 12 -pow-puzzle argon2id
     
Put a file :

     go run ./cmd/revika-ctl put -bootstrap /ip4/127.0.0.1/tcp/4001/p2p/xxxxxx -signkey user.sign.key -r /path/to/your/root/folder

retrieve a file :

     go run ./cmd/revika-ctl get -bootstrap /ip4/188.165.234.144/tcp/4001/p2p/xxxxxx -manifest manifest.json
