package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"

	"revika/internal/cap"
	"revika/internal/crypto"
	"revika/internal/net"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// inProcessNode starts a Node serving a MemStore on a real in-process libp2p
// host, plus a client host connected to it, and returns a NetStore over the
// node — the same wiring dial() produces, minus the multiaddr parsing.
func inProcessNode(t *testing.T) *net.NetStore {
	t.Helper()
	server, err := net.NewHost(net.HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("server host: %v", err)
	}
	t.Cleanup(func() { server.Close() })
	net.NewServer(store.NewMemStore(), nil).Register(server)

	client, err := net.NewHost(net.HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("client host: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := net.Connect(ctx, client, peer.AddrInfo{ID: server.ID(), Addrs: server.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	return net.NewNetStore(client, server.ID())
}

// TestManifestRoundTrip checks the JSON serialization preserves a manifest.
func TestManifestRoundTrip(t *testing.T) {
	orig := pipeline.FileManifest{
		Name:   "photo.jpg",
		Params: pipeline.DefaultConfig(),
		Size:   4242,
		Chunks: []pipeline.ChunkRef{
			{Key: crypto32(1), Shards: []store.ShardID{hash32(10), hash32(11)}},
			{Key: crypto32(2), Shards: []store.ShardID{hash32(20)}},
		},
	}
	data, err := encodeManifest(orig)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := decodeManifest(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Name != orig.Name || got.Size != orig.Size || got.Params != orig.Params || len(got.Chunks) != len(orig.Chunks) {
		t.Fatalf("header mismatch: %+v vs %+v", got, orig)
	}
	for i := range orig.Chunks {
		if got.Chunks[i].Key != orig.Chunks[i].Key {
			t.Fatalf("chunk %d key mismatch", i)
		}
		if len(got.Chunks[i].Shards) != len(orig.Chunks[i].Shards) {
			t.Fatalf("chunk %d shard count mismatch", i)
		}
		for j := range orig.Chunks[i].Shards {
			if got.Chunks[i].Shards[j] != orig.Chunks[i].Shards[j] {
				t.Fatalf("chunk %d shard %d mismatch", i, j)
			}
		}
	}
}

func TestDecodeManifestRejectsGarbage(t *testing.T) {
	if _, err := decodeManifest([]byte("not json")); err == nil {
		t.Fatal("decodeManifest accepted non-JSON")
	}
	if _, err := decodeManifest([]byte(`{"version":1,"chunks":[{"key":"zz","shards":[]}]}`)); err == nil {
		t.Fatal("decodeManifest accepted a bad-hex key")
	}
}

// TestEndToEndPutShareGet is the whole point: store a file on a node, wrap its
// manifest to a recipient's public key, then reconstruct the file by unwrapping
// with the recipient's private key — proving put → share → get works and is
// genuinely end-to-end (only the right key opens it).
func TestEndToEndPutShareGet(t *testing.T) {
	s := inProcessNode(t)
	ctx := context.Background()

	// A file spanning several chunks.
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.bin")
	orig := make([]byte, 200*1024+7)
	for i := range orig {
		orig[i] = byte(i*13 + 1)
	}
	if err := os.WriteFile(inPath, orig, 0o600); err != nil {
		t.Fatal(err)
	}

	// put: store on the node, serialize the manifest.
	cfg := pipeline.Config{ChunkSize: 64 * 1024, Params: pipeline.DefaultConfig().Params}
	m, err := runStore(ctx, s, cfg, inPath)
	if err != nil {
		t.Fatalf("runStore: %v", err)
	}
	manifestJSON, err := encodeManifest(m)
	if err != nil {
		t.Fatal(err)
	}

	// share: wrap the manifest to the recipient's public key.
	priv, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cap.Wrap(pub, manifestJSON)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// get: recipient unwraps with their private key and reconstructs.
	derivedPub, err := priv.Public()
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := cap.Unwrap(priv, derivedPub, sealed)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	m2, err := decodeManifest(unwrapped)
	if err != nil {
		t.Fatalf("decode unwrapped manifest: %v", err)
	}
	var buf bytes.Buffer
	if err := runLoad(ctx, s, m2, &buf); err != nil {
		t.Fatalf("runLoad: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), orig) {
		t.Fatal("reconstructed file does not match original")
	}

	// Negative: a different recipient cannot open the cap.
	wrongPriv, wrongPub, _ := cap.GenerateIdentity()
	if _, err := cap.Unwrap(wrongPriv, wrongPub, sealed); !errors.Is(err, cap.ErrUnwrap) {
		t.Fatalf("wrong recipient opened the cap: err = %v", err)
	}
}

// TestResolveRecipientFromFile checks the @file form used by `share -to`.
func TestResolveRecipientFromFile(t *testing.T) {
	_, pub, _ := cap.GenerateIdentity()
	dir := t.TempDir()
	pubFile := filepath.Join(dir, "bob.pub")
	if err := os.WriteFile(pubFile, []byte(pub.String()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := resolveRecipient("@" + pubFile)
	if err != nil {
		t.Fatalf("resolveRecipient @file: %v", err)
	}
	if got != pub {
		t.Fatal("recipient from @file mismatch")
	}

	// Literal base64 form too.
	got, err = resolveRecipient(pub.String())
	if err != nil || got != pub {
		t.Fatalf("resolveRecipient literal: %v, %v", got, err)
	}
}

// startStorageNode spins up a server-role storage node on a private in-process
// revika DHT: a libp2p host with the shard handlers registered, a DHT joined to
// the given bootstrap peer (empty for the seed), and the storage-node
// advertisement running so clients can discover it. It returns a dialable
// bootstrap multiaddr (with /p2p/<id>) and the node's peer ID.
func startStorageNode(t *testing.T, ctx context.Context, bootstrap string) (string, peer.ID) {
	t.Helper()
	h, err := net.NewHost(net.HostConfig{ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("node host: %v", err)
	}
	t.Cleanup(func() { h.Close() })

	var boots []string
	if bootstrap != "" {
		boots = []string{bootstrap}
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	disc, err := net.NewDiscovery(dctx, h, net.DiscoveryConfig{Mode: net.DHTModeServer, Bootstrap: boots})
	if err != nil {
		t.Fatalf("node discovery: %v", err)
	}
	// Registered after the host so cleanup (LIFO) closes the DHT before the host.
	t.Cleanup(func() { disc.Close() })

	net.NewServer(store.NewMemStore(), nil).Register(h)
	disc.AdvertiseLoop(ctx) // advertise as a storage node so clients can find us

	var addr string
	for _, a := range h.Addrs() {
		addr = a.String() + "/p2p/" + h.ID().String()
		break
	}
	if addr == "" {
		t.Fatal("node has no listen address")
	}
	return addr, h.ID()
}

// TestDiscoverNodeInfos exercises the discovery behind the `nodes` command: two
// storage nodes advertise themselves on a private DHT, and a client that joins
// through the seed must become aware of both and report them reachable.
func TestDiscoverNodeInfos(t *testing.T) {
	ctx := t.Context() // canceled at test end, stopping the advertise loops

	// Two storage nodes; the second bootstraps off the first (the seed).
	seedAddr, seedID := startStorageNode(t, ctx, "")
	_, node2ID := startStorageNode(t, ctx, seedAddr)

	// The client joins the DHT via the seed — exactly as `nodes -bootstrap` does.
	h, disc, closer, err := joinDHT(ctx, []string{seedAddr}, false)
	if err != nil {
		t.Fatalf("joinDHT: %v", err)
	}
	defer closer()

	nodes := discoverNodeInfos(ctx, h, disc)

	// Both advertised nodes should be discovered, reachable, and carry addresses.
	reachable := map[peer.ID]nodeInfo{}
	for _, n := range nodes {
		if n.Reachable {
			reachable[n.Info.ID] = n
		}
	}
	for _, want := range []peer.ID{seedID, node2ID} {
		n, ok := reachable[want]
		if !ok {
			t.Fatalf("node %s not discovered as reachable; got %+v", want, nodes)
		}
		if len(n.Info.Addrs) == 0 {
			t.Fatalf("node %s discovered with no advertised addresses", want)
		}
	}
	// The client itself never advertised as a storage node, so it must not appear.
	for _, n := range nodes {
		if n.Info.ID == h.ID() {
			t.Fatalf("client host %s listed itself as a storage node", h.ID())
		}
	}
}

// --- small test helpers ---

func crypto32(b byte) (k crypto.Key) {
	for i := range k {
		k[i] = b
	}
	return
}

func hash32(b byte) (id store.ShardID) {
	for i := range id {
		id[i] = b
	}
	return
}
