package db

import (
	"testing"
)

func TestOpenEnablesForeignKeysAndCreatesSchema(t *testing.T) {
	database, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var foreignKeys int
	if err := database.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys = %d, want 1", foreignKeys)
	}
	var tables int
	if err := database.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN ('identities', 'items', 'manifests', 'capabilities', 'sync_anchors')`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 5 {
		t.Fatalf("core table count = %d, want 5", tables)
	}
}
