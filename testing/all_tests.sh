#! /bin/bash

go test ./... -coverpkg=./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

go run ./cmd/revika-ctl connect -root .test_ws -label "test node" /ip4/127.0.0.1/tcp/4002/p2p/$SEED_ADDR

go run ./cmd/revika-ctl cp -root .test_ws .test rvk:

go run ./cmd/revika-ctl ls -root .test_ws -l rvk:

go run ./cmd/revika-ctl connect -root .test_guest /ip4/127.0.0.1/tcp/4002/p2p/$SEED_ADDR

go run ./cmd/revika-ctl share -root .test_ws -to .test_guest/keys/user.pub -o share.root.json rvk:.test/testfile.bin

go run ./cmd/revika-ctl share -root .test_ws -to .test_guest/keys/user.pub -o shared-dir.root.json rvk:
go run ./cmd/revika-ctl ls -root shared-dir.root.json -key .test_guest/keys/user.key -node /ip4/127.0.0.1/tcp/4002/p2p/$SEED_ADDR rvk:
go run ./cmd/revika-ctl cp -root shared-dir.root.json -key .test_guest/keys/user.key -node /ip4/127.0.0.1/tcp/4002/p2p/$SEED_ADDR rvk: .guest_test

go run ./cmd/revika-ctl ls -root .test_guest -owner .test_ws/keys/user.sign.pub

go run ./cmd/revika-ctl revoke -root .test_ws rvk:

go run ./cmd/revika-ctl ls -root .test_guest -owner .test_ws/keys/user.sign.pub
go run ./cmd/revika-ctl cp -root shared-dir.root.json -key .test_guest/keys/user.key -node /ip4/127.0.0.1/tcp/4002/p2p/$SEED_ADDR rvk: .guest_revoked   # expected to fail
