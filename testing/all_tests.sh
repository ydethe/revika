#! /bin/bash

go test ./... -coverpkg=./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

go run ./cmd/revika-ctl connect -root .test_ws -label "test node" /ip4/127.0.0.1/tcp/4002/p2p/$SEED_ADDR

go run ./cmd/revika-ctl cp -root .test_ws .test rvk:

go run ./cmd/revika-ctl ls -root .test_ws -l rvk:

# --- device management under the offline master credential (Architecture §3.7.2) ---
# The master credential is .test_ws/keys/user.sign.key; a device is one ML-KEM keypair
# authorized to open the sealed self-root companion.

# Bootstrap the device-authorization record (.test_ws/devices.json) with this device.
go run ./cmd/revika-ctl device init -root .test_ws -label "laptop"
go run ./cmd/revika-ctl device list -root .test_ws
go run ./cmd/revika-ctl device id -root .test_ws

# A second device's ML-KEM keypair (a bare keygen stands in for the second machine;
# enrollment only needs its .pub).
go run ./cmd/revika-ctl keygen -key .test_dev2/user -pow-difficulty 0

# Enroll it from the master: reseals the companion to {laptop, phone} and republishes.
go run ./cmd/revika-ctl device enroll -root .test_ws -label "phone" .test_dev2/user.pub
go run ./cmd/revika-ctl device list -root .test_ws

# Read-revoke it: reseals the companion to the surviving device set only (forward-only).
DEV2_ID=$(go run ./cmd/revika-ctl device id -root .test_dev2 | awk '/device id:/ {print $3}')
go run ./cmd/revika-ctl device revoke -root .test_ws "$DEV2_ID"
go run ./cmd/revika-ctl device list -root .test_ws

go run ./cmd/revika-ctl connect -root .test_guest /ip4/127.0.0.1/tcp/4002/p2p/$SEED_ADDR

go run ./cmd/revika-ctl share -root .test_ws -to .test_guest/keys/user.pub -o share.root.json rvk:.test/testfile.bin

go run ./cmd/revika-ctl share -root .test_ws -to .test_guest/keys/user.pub -o shared-dir.root.json rvk:
go run ./cmd/revika-ctl ls -root shared-dir.root.json -key .test_guest/keys/user.key -node /ip4/127.0.0.1/tcp/4002/p2p/$SEED_ADDR rvk:
go run ./cmd/revika-ctl cp -root shared-dir.root.json -key .test_guest/keys/user.key -node /ip4/127.0.0.1/tcp/4002/p2p/$SEED_ADDR rvk: .guest_test

go run ./cmd/revika-ctl ls -root .test_guest -owner .test_ws/keys/user.sign.pub

go run ./cmd/revika-ctl revoke -root .test_ws rvk:

go run ./cmd/revika-ctl ls -root .test_guest -owner .test_ws/keys/user.sign.pub
go run ./cmd/revika-ctl cp -root shared-dir.root.json -key .test_guest/keys/user.key -node /ip4/127.0.0.1/tcp/4002/p2p/$SEED_ADDR rvk: .guest_revoked   # expected to fail
