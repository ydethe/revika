To run an end-to-end test :

     go run ./cmd/revika-node -listen /ip4/127.0.0.1/tcp/4001 &   # note printed /p2p/ multiaddr
     NODE=/ip4/127.0.0.1/tcp/4001/p2p/<peerid>
     go run ./cmd/revika-ctl keygen -key /tmp/bob            # Bob's identity; prints Bob's pubkey
     echo "hello revika" > /tmp/in.txt
     go run ./cmd/revika-ctl put   -node $NODE -manifest /tmp/f.json /tmp/in.txt
     go run ./cmd/revika-ctl share -manifest /tmp/f.json -to <bob-pubkey> -o /tmp/f.cap
     go run ./cmd/revika-ctl get   -node $NODE -cap /tmp/f.cap -key /tmp/bob.key -o /tmp/out.txt
     diff /tmp/in.txt /tmp/out.txt        # identical
