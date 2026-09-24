package keymanager

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestDiskManagerProtectsKeyFiles(t *testing.T) {
	dir := t.TempDir()
	manager, err := NewDiskManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Open(context.Background(), EnvironmentStaging); err != nil {
		t.Fatal(err)
	}
	key, err := manager.Generate(context.Background(), KeySpec{Algorithm: "ECDSA_P256"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Signer(context.Background(), key.ID); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("key directory entries = %d, %v", len(entries), err)
	}
	info, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %o, want 600", info.Mode().Perm())
	}
}

func TestDiskManagerRejectsTemporaryProductionPath(t *testing.T) {
	manager, err := NewDiskManager("/tmp/qredin-test-keys")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Open(context.Background(), EnvironmentProduction); err == nil || !errors.Is(err, ErrNotProductionSafe) {
		t.Fatalf("Open error = %v, want ErrNotProductionSafe", err)
	}
}
