//go:build integration
// +build integration

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qredin/qredin/authentication/internal/attestation"
	"github.com/qredin/qredin/authentication/internal/registration"
	"github.com/qredin/qredin/authentication/internal/store"
	"github.com/qredin/qredin/pkg/spiffeid"
)

const testConnStr = "postgres://postgres:test@localhost:5433/qredin?sslmode=disable"

func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, testConnStr)
	if err != nil {
		t.Fatalf("connecting to postgres: %v", err)
	}
	pool.Exec(ctx, `DROP TABLE IF EXISTS qredin_audit_events CASCADE`)
	pool.Exec(ctx, `DROP TABLE IF EXISTS qredin_registrations CASCADE`)
	pool.Exec(ctx, `DROP TABLE IF EXISTS qredin_authorities CASCADE`)
	pool.Exec(ctx, `DROP TABLE IF EXISTS qredin_trust_domains CASCADE`)
	pool.Exec(ctx, `DROP TABLE IF EXISTS qredin_registration_approvals CASCADE`)
	pool.Exec(ctx, `DROP TABLE IF EXISTS qredin_schema_migrations CASCADE`)
	return pool
}

func setupSchema(t *testing.T, pool *pgxpool.Pool, td string) {
	t.Helper()
	if err := store.ApplyMigrations(context.Background(), pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	_, err := pool.Exec(context.Background(),
		`INSERT INTO qredin_trust_domains(trust_domain, environment_id, status) VALUES ($1, $2, $3)`,
		td, "test", "active")
	if err != nil {
		t.Fatalf("seeding trust domain: %v", err)
	}
}

func makeEntry(id, tdName string) registration.Entry {
	td := spiffeid.RequireTrustDomainFromString(tdName)
	workload := spiffeid.RequireFromString("spiffe://" + tdName + "/ns/payments/sa/api")
	parent := spiffeid.RequireFromString("spiffe://" + tdName + "/node/node-1")
	selectors, _ := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "1000"})
	return registration.Entry{
		ID: id, TenantID: "tenant-1", EnvironmentID: "test",
		TrustDomain: td, WorkloadID: workload, ParentAgentID: parent,
		Selectors: selectors, Status: registration.StatusActive,
	}
}

func TestApplyMigrations(t *testing.T) {
	pool := newTestPool(t)
	defer pool.Close()
	setupSchema(t, pool, "test1.example.com")

	var count int
	err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM qredin_schema_migrations`).Scan(&count)
	if err != nil {
		t.Fatalf("querying migrations: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 migrations recorded, got %d", count)
	}
}

func TestTransactionRollbackOnError(t *testing.T) {
	pool := newTestPool(t)
	defer pool.Close()
	setupSchema(t, pool, "test2.example.com")

	repo, err := store.NewRegistrationRepository(pool)
	if err != nil {
		t.Fatalf("NewRegistrationRepository: %v", err)
	}

	entry := makeEntry("test-rollback", "test2.example.com")
	rev, err := repo.Put(context.Background(), entry, nil)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// First update succeeds, then stale revision should cause an error.
	err = store.WithTransaction(context.Background(), pool, func(tx pgx.Tx) error {
		newRev, err := repo.SetStatusTx(tx, context.Background(), entry.ID, "suspended", rev)
		if err != nil {
			return err
		}
		_ = newRev
		// Stale revision should cause SetStatusTx to return an error.
		_, err = repo.SetStatusTx(tx, context.Background(), entry.ID, "active", rev)
		return err
	})
	if err == nil {
		t.Fatal("expected WithTransaction to return error")
	}
}

func TestConcurrentWriterConflict(t *testing.T) {
	pool := newTestPool(t)
	defer pool.Close()
	setupSchema(t, pool, "test3.example.com")

	repo, err := store.NewRegistrationRepository(pool)
	if err != nil {
		t.Fatalf("NewRegistrationRepository: %v", err)
	}

	entry := makeEntry("test-concurrent", "test3.example.com")
	rev, err := repo.Put(context.Background(), entry, nil)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	err1 := store.WithTransaction(context.Background(), pool, func(tx pgx.Tx) error {
		newRev, err := repo.SetStatusTx(tx, context.Background(), entry.ID, "suspended", rev)
		if err != nil {
			return err
		}
		_ = newRev
		return nil
	})

	err2 := store.WithTransaction(context.Background(), pool, func(tx pgx.Tx) error {
		newRev, err := repo.SetStatusTx(tx, context.Background(), entry.ID, "revoked", rev)
		if err != nil {
			return err
		}
		_ = newRev
		return nil
	})

	if err1 == nil && err2 == nil {
		t.Fatal("expected at least one revision conflict")
	}
}

func TestOptimisticRevisionConflict(t *testing.T) {
	pool := newTestPool(t)
	defer pool.Close()
	setupSchema(t, pool, "test4.example.com")

	repo, err := store.NewRegistrationRepository(pool)
	if err != nil {
		t.Fatalf("NewRegistrationRepository: %v", err)
	}

	entry := makeEntry("test-rev-conflict", "test4.example.com")
	rev, err := repo.Put(context.Background(), entry, nil)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Use stale revision to trigger conflict
	staleRev := rev + 999
	_, err = repo.Put(context.Background(), entry, &staleRev)
	if !errors.Is(err, store.ErrRevisionConflict) {
		t.Fatalf("expected ErrRevisionConflict, got %v", err)
	}
}

func TestAuditEventPersistence(t *testing.T) {
	pool := newTestPool(t)
	defer pool.Close()
	setupSchema(t, pool, "test5.example.com")

	auditRepo, err := store.NewAuditRepository(pool)
	if err != nil {
		t.Fatalf("NewAuditRepository: %v", err)
	}

	eventID := "12345678-1234-1234-1234-123456789abc"
	err = auditRepo.Append(context.Background(), store.AuditEvent{
		EventID:       eventID,
		EventType:     "registration.put",
		TenantID:      "tenant-1",
		EnvironmentID: "test",
		Payload:       []byte(`{"test": true}`),
		OccurredAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	var storedEventID string
	err = pool.QueryRow(context.Background(),
		`SELECT event_id FROM qredin_audit_events WHERE event_id = $1`, eventID).
		Scan(&storedEventID)
	if err != nil {
		t.Fatalf("querying audit event: %v", err)
	}
	if storedEventID != eventID {
		t.Fatalf("stored event ID = %q, want %q", storedEventID, eventID)
	}

	err = auditRepo.Append(context.Background(), store.AuditEvent{
		EventID:       eventID,
		EventType:     "registration.put",
		TenantID:      "tenant-1",
		EnvironmentID: "test",
		Payload:       []byte(`{"test": true}`),
		OccurredAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("Append duplicate: %v", err)
	}

	var count int
	err = pool.QueryRow(context.Background(),
		`SELECT count(*) FROM qredin_audit_events WHERE event_id = $1`, eventID).Scan(&count)
	if err != nil {
		t.Fatalf("querying audit events: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 audit event, got %d", count)
	}
}

func TestRegistrationApprovalWorkflow(t *testing.T) {
	pool := newTestPool(t)
	defer pool.Close()
	setupSchema(t, pool, "test6.example.com")

	regRepo, err := store.NewRegistrationRepository(pool)
	if err != nil {
		t.Fatalf("NewRegistrationRepository: %v", err)
	}
	approvalRepo, err := store.NewRegistrationApprovalRepository(pool)
	if err != nil {
		t.Fatalf("NewRegistrationApprovalRepository: %v", err)
	}

	entry := makeEntry("test-approval", "test6.example.com")
	rev, err := regRepo.Put(context.Background(), entry, nil)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	if err := approvalRepo.Approve(context.Background(), entry.ID, "operator-1"); err != nil {
		t.Fatalf("Approve 1: %v", err)
	}
	if err := approvalRepo.Approve(context.Background(), entry.ID, "operator-2"); err != nil {
		t.Fatalf("Approve 2: %v", err)
	}

	newRev, err := approvalRepo.Activate(context.Background(), entry.ID, rev)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if newRev != rev+1 {
		t.Fatalf("new revision = %d, want %d", newRev, rev+1)
	}
}
