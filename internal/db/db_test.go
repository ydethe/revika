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
	want := []string{
		"identities", "root_pointers", "items", "manifests", "chunks", "providers",
		"shards", "capabilities", "vector_clocks", "crdt_operations", "sync_anchors", "repair_jobs",
	}
	for _, name := range want {
		var count int
		if err := database.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("table %q present = %d, want 1", name, count)
		}
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	database, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	// A second migrate pass must apply no new migrations and must not error.
	if err := database.migrate(); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := database.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != len(migrations) {
		t.Fatalf("schema version = %d, want %d", version, len(migrations))
	}
}

func TestFileKeysTable(t *testing.T) {
	database, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`INSERT INTO file_keys(item_id, encryption_key, created_at_ns) VALUES (?, ?, ?)`, "item-1", []byte("key-bytes"), int64(1)); err != nil {
		t.Fatal(err)
	}
	var key []byte
	if err := database.QueryRow(`SELECT encryption_key FROM file_keys WHERE item_id = ?`, "item-1").Scan(&key); err != nil {
		t.Fatal(err)
	}
	if string(key) != "key-bytes" {
		t.Fatalf("encryption_key = %q, want %q", key, "key-bytes")
	}
}
