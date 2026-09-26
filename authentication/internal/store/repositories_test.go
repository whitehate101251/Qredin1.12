package store

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestAuthorityTransitionsAreExplicit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		from, to string
		want     bool
	}{
		{"prepared", "active", true},
		{"active", "old", true},
		{"active", "tainted", true},
		{"old", "revoked", true},
		{"tainted", "revoked", true},
		{"prepared", "revoked", false},
		{"revoked", "active", false},
		{"old", "active", false},
	}
	for _, test := range tests {
		if got := validAuthorityTransition(test.from, test.to); got != test.want {
			t.Errorf("transition %s -> %s = %v, want %v", test.from, test.to, got, test.want)
		}
	}
}

func TestStoreRejectsInvalidDependenciesAndAuditEvents(t *testing.T) {
	t.Parallel()
	if _, err := NewRegistrationRepository(nil); err == nil {
		t.Error("NewRegistrationRepository accepted nil pool")
	}
	if _, err := NewTrustDomainRepository(nil); err == nil {
		t.Error("NewTrustDomainRepository accepted nil pool")
	}
	if _, err := NewAuthorityRepository(nil); err == nil {
		t.Error("NewAuthorityRepository accepted nil pool")
	}
	if _, err := NewAuditRepository(nil); err == nil {
		t.Error("NewAuditRepository accepted nil pool")
	}
	if err := WithTransaction(context.Background(), nil, func(pgx.Tx) error { return nil }); err == nil {
		t.Error("WithTransaction accepted nil pool")
	}

	if err := (&AuditRepository{}).Append(context.Background(), AuditEvent{}); err == nil {
		t.Error("Append accepted an empty audit event")
	}
	if !json.Valid(json.RawMessage(`{"event":"ok"}`)) {
		t.Fatal("test JSON is invalid")
	}
	if errors.Is(ErrRevisionConflict, ErrNotFound) {
		t.Fatal("store sentinel errors unexpectedly overlap")
	}
}

func TestMigrationVersionValidation(t *testing.T) {
	t.Parallel()
	if got, err := migrationVersion("migrations/002_authority_revisions.sql"); err != nil || got != 2 {
		t.Fatalf("migrationVersion = %d, %v", got, err)
	}
	for _, name := range []string{"migration.sql", "x_bad.sql", "000_bad.sql"} {
		if _, err := migrationVersion(name); err == nil {
			t.Errorf("migrationVersion(%q) accepted invalid name", name)
		}
	}
}

func TestMigrationFilesAreOrdered(t *testing.T) {
	t.Parallel()
	files, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		t.Fatalf("listing migrations: %v", err)
	}
	sort.Strings(files)
	if len(files) != 6 {
		t.Fatalf("expected 6 migrations, got %d", len(files))
	}
	expected := []string{
		"migrations/001_initial.sql",
		"migrations/002_authority_revisions.sql",
		"migrations/003_registration_approvals.sql",
		"migrations/004_policies.sql",
		"migrations/005_policy_approvals.sql",
		"migrations/006_audit_correlation.sql",
	}
	for i, expectedName := range expected {
		if got := path.Base(files[i]); got != path.Base(expectedName) {
			t.Errorf("migration %d: expected %s, got %s", i+1, path.Base(expectedName), got)
		}
	}
}

func TestMigrationChecksumsMatchEmbeddedFiles(t *testing.T) {
	t.Parallel()
	files, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		t.Fatalf("listing migrations: %v", err)
	}
	sort.Strings(files)
	for _, name := range files {
		contents, err := migrationFiles.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if len(contents) == 0 {
			t.Fatalf("migration %s is empty", name)
		}
	}
}

func TestMigrationCompatibility(t *testing.T) {
	t.Parallel()
	files, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		t.Fatalf("listing migrations: %v", err)
	}
	sort.Strings(files)
	for _, name := range files {
		contents, err := migrationFiles.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if !strings.Contains(string(contents), "CREATE TABLE") && !strings.Contains(string(contents), "ALTER TABLE") {
			t.Errorf("migration %s lacks DDL statements", name)
		}
	}
}

func TestMigrationVersionOrdering(t *testing.T) {
	t.Parallel()
	files, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		t.Fatalf("listing migrations: %v", err)
	}
	sort.Strings(files)
	var lastVersion int64
	for _, name := range files {
		version, err := migrationVersion(name)
		if err != nil {
			t.Fatalf("version of %s: %v", name, err)
		}
		if version <= lastVersion {
			t.Errorf("migration %s has version %d, expected > %d", name, version, lastVersion)
		}
		lastVersion = version
	}
}

func TestMigrationVersionExtraction(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		want    int64
		wantErr bool
	}{
		{"migrations/001_initial.sql", 1, false},
		{"migrations/002_authority_revisions.sql", 2, false},
		{"migrations/003_registration_approvals.sql", 3, false},
		{"migration.sql", 0, true},
		{"x_bad.sql", 0, true},
		{"000_bad.sql", 0, true},
		{"99999_last.sql", 99999, false},
	}
	for _, test := range tests {
		got, err := migrationVersion(test.name)
		if test.wantErr {
			if err == nil {
				t.Errorf("migrationVersion(%q) should error", test.name)
			}
		} else {
			if err != nil {
				t.Errorf("migrationVersion(%q) = %v, want %d", test.name, err, test.want)
			} else if got != test.want {
				t.Errorf("migrationVersion(%q) = %d, want %d", test.name, got, test.want)
			}
		}
	}
}
