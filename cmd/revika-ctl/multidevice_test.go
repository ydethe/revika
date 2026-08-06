package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"revika/internal/cap"
	"revika/internal/manifest"
	"revika/internal/pipeline"
	"revika/internal/store"
)

// device is a test stand-in for one machine sharing the owner keys: its own
// workspace files (root.json/base.json), its own conflict-copy tag, and its own
// DHT discovery, all over a shared content store.
type device struct {
	cc   commitConfig
	disc fullRootPublisher
	s    store.Store
	cfg  pipeline.Config
}

// put stores data at rvk-path name grafted onto this device's *current* root
// (loaded from its root.json, exactly as cmdCp does) and commits — driving the
// full read-merge-publish loop.
func (d *device) put(t *testing.T, ctx context.Context, name string, data []byte) {
	t.Helper()
	prev, exists, sealed, err := loadRoot(d.cc.file, "")
	if err != nil {
		t.Fatalf("loadRoot %s: %v", d.cc.file, err)
	}
	root := prev.Root
	if !exists {
		root, err = manifest.StoreDir(ctx, d.s, d.cfg, manifest.NewDir(pipeline.Metadata{}))
		if err != nil {
			t.Fatalf("empty root: %v", err)
		}
	}
	fm, err := pipeline.StoreFile(ctx, d.s, d.cfg, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("store %s: %v", name, err)
	}
	child, err := manifest.StoreFileManifest(ctx, d.s, d.cfg, fm)
	if err != nil {
		t.Fatalf("store manifest %s: %v", name, err)
	}
	newRoot, err := manifest.Graft(ctx, d.s, d.cfg, root, name, child, statFromManifest(fm))
	if err != nil {
		t.Fatalf("graft %s: %v", name, err)
	}
	if err := commitRoot(ctx, d.cc, newRoot, prev, exists, sealed, d.disc); err != nil {
		t.Fatalf("commit %s: %v", name, err)
	}
}

// tip resolves this device's currently published root to its decryptable form
// (verify-root from the DHT + companion open), the view any device would rebuild.
func (d *device) tip(t *testing.T, ctx context.Context, owner cap.SignPubKey) manifest.ReadCap {
	t.Helper()
	verify, ok, err := d.disc.GetRoot(ctx, owner)
	if err != nil || !ok {
		t.Fatalf("GetRoot: ok=%v err=%v", ok, err)
	}
	full, ok, err := d.disc.GetFullRoot(ctx, owner, d.cc.priv, d.cc.pub, verify.Root)
	if err != nil || !ok {
		t.Fatalf("GetFullRoot: ok=%v err=%v", ok, err)
	}
	return full
}

func resolveFile(t *testing.T, ctx context.Context, s store.Store, root manifest.ReadCap, p string) []byte {
	t.Helper()
	c, err := manifest.Resolve(ctx, s, root, p)
	if err != nil {
		t.Fatalf("resolve %s: %v", p, err)
	}
	fm, err := manifest.LoadFileManifest(ctx, s, c)
	if err != nil {
		t.Fatalf("load manifest %s: %v", p, err)
	}
	var buf bytes.Buffer
	if err := pipeline.LoadFile(ctx, s, fm, &buf); err != nil {
		t.Fatalf("load file %s: %v", p, err)
	}
	return buf.Bytes()
}

func dirNames(t *testing.T, ctx context.Context, s store.Store, root manifest.ReadCap) []string {
	t.Helper()
	dm, err := manifest.LoadDir(ctx, s, root)
	if err != nil {
		t.Fatalf("load dir: %v", err)
	}
	var names []string
	for _, e := range dm.Entries {
		names = append(names, e.Name)
	}
	return names
}

// TestMultiDeviceConverge is the Stage-3 crux over a real in-process DHT: two
// devices sharing one owner key commit divergent roots against a shared content
// store; each commit reads the other's sealed self-root, three-way-merges, and
// publishes a root containing BOTH sides. Disjoint edits merge cleanly; a
// colliding path yields one conflict copy with both versions kept — never a
// silent loss.
func TestMultiDeviceConverge(t *testing.T) {
	ctx := t.Context()

	seedAddr, _ := startStorageNode(t, ctx, "")
	_, discA, closeA, err := joinDHT(ctx, []string{seedAddr})
	if err != nil {
		t.Fatalf("joinDHT A: %v", err)
	}
	defer closeA()
	_, discB, closeB, err := joinDHT(ctx, []string{seedAddr})
	if err != nil {
		t.Fatalf("joinDHT B: %v", err)
	}
	defer closeB()

	// One shared content store models shards being globally reachable; the two
	// discoveries carry the divergent root/companion records.
	s := store.NewMemStore()
	cfg := pipeline.DefaultConfig()

	sk, owner, err := cap.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := cap.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	mk := func(dir, tag string, disc fullRootPublisher) *device {
		return &device{
			cc: commitConfig{
				file:     dir + "/root.json",
				basePath: dir + "/base.json",
				signer:   sk,
				mlkemOK:  true,
				priv:     priv,
				pub:      pub,
				label:    func(name string) string { return name + ".conflict-" + tag },
				s:        s,
				cfg:      cfg,
			},
			disc: disc,
			s:    s,
			cfg:  cfg,
		}
	}

	cctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()

	A := mk(t.TempDir(), "A", discA)
	B := mk(t.TempDir(), "B", discB)

	// A publishes {a.txt}; B, which never saw A, writes {b.txt} and its commit
	// must fetch A's companion and merge to {a.txt, b.txt}.
	A.put(t, cctx, "a.txt", []byte("alpha"))
	B.put(t, cctx, "b.txt", []byte("bravo"))

	merged := B.tip(t, cctx, owner)
	if got := dirNames(t, cctx, s, merged); len(got) != 2 {
		t.Fatalf("merged root has %v, want a.txt and b.txt", got)
	}
	if got := resolveFile(t, cctx, s, merged, "a.txt"); !bytes.Equal(got, []byte("alpha")) {
		t.Fatalf("a.txt = %q, want alpha", got)
	}
	if got := resolveFile(t, cctx, s, merged, "b.txt"); !bytes.Equal(got, []byte("bravo")) {
		t.Fatalf("b.txt = %q, want bravo", got)
	}

	// Genuine collision: B writes same.txt=fromB (folding in the current tip),
	// then A — whose local base still predates that — writes same.txt=fromA. A's
	// merge must keep both, filing A's version as a conflict copy.
	B.put(t, cctx, "same.txt", []byte("fromB"))
	A.put(t, cctx, "same.txt", []byte("fromA"))

	final := A.tip(t, cctx, owner)
	names := dirNames(t, cctx, s, final)
	var hasSame, hasConflict bool
	for _, n := range names {
		switch n {
		case "same.txt":
			hasSame = true
		case "same.txt.conflict-A":
			hasConflict = true
		}
	}
	if !hasSame || !hasConflict {
		t.Fatalf("collision did not produce both same.txt and a conflict copy; got %v", names)
	}
	got1 := resolveFile(t, cctx, s, final, "same.txt")
	got2 := resolveFile(t, cctx, s, final, "same.txt.conflict-A")
	if bytes.Equal(got1, got2) {
		t.Fatal("conflict copy is identical to the kept version; a side was lost")
	}
	for _, want := range [][]byte{[]byte("fromA"), []byte("fromB")} {
		if !bytes.Equal(got1, want) && !bytes.Equal(got2, want) {
			t.Fatalf("neither surviving copy equals %q (got %q and %q)", want, got1, got2)
		}
	}
	// a.txt and b.txt from the first phase must still be present and intact.
	if got := resolveFile(t, cctx, s, final, "a.txt"); !bytes.Equal(got, []byte("alpha")) {
		t.Fatalf("a.txt lost across collision: %q", got)
	}
	if got := resolveFile(t, cctx, s, final, "b.txt"); !bytes.Equal(got, []byte("bravo")) {
		t.Fatalf("b.txt lost across collision: %q", got)
	}
}
