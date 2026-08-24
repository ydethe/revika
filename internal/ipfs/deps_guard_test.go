package ipfs

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// forbiddenImports are packages that the IPFS port and its non-adapter
// consumers must never import. Only internal/ipfs/kubo may reach these.
var forbiddenImports = []string{
	"github.com/ipfs/go-ipfs-api",
	"github.com/ipfs/go-cid",
	"github.com/ipfs/kubo",
	"github.com/libp2p/",
}

// TestPortHasNoForbiddenImports asserts the port itself only speaks revika
// terms and never leaks IPFS/CID/libp2p types.
func TestPortHasNoForbiddenImports(t *testing.T) {
	assertNoForbiddenImports(t, "port.go")
}

// TestModelHasNoForbiddenImports enforces the invariant on pkg/model: it must
// remain free of IPFS/CID/libp2p imports.
func TestModelHasNoForbiddenImports(t *testing.T) {
	modelDir := filepath.Join("..", "..", "pkg", "model")
	entries, err := os.ReadDir(modelDir)
	if err != nil {
		t.Fatalf("failed to read %s: %v", modelDir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		assertNoForbiddenImports(t, filepath.Join(modelDir, e.Name()))
	}
}

func assertNoForbiddenImports(t *testing.T, path string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("failed to parse %s: %v", path, err)
	}
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		for _, bad := range forbiddenImports {
			if strings.HasPrefix(p, bad) {
				t.Errorf("%s imports forbidden package %q", path, p)
			}
		}
	}
}
