//go:build integration

package store_test

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/qredin/qredin/authentication/internal/attestation"
	"github.com/qredin/qredin/authentication/internal/registration"
	"github.com/qredin/qredin/authentication/internal/store"
	"github.com/qredin/qredin/pkg/spiffeid"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("QREDIN_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("QREDIN_TEST_POSTGRES_DSN not set")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := store.ApplyMigrations(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestConcurrentWriterStress(t *testing.T) {
	pool := testPool(t)
	repo, err := store.NewRegistrationRepository(pool)
	if err != nil {
		t.Fatal(err)
	}

	td := spiffeid.RequireTrustDomainFromString("spiffe://stress.example.com")
	selectors, _ := attestation.NewSelectors(attestation.Selector{Type: "unix.uid", Value: "1000"})
	entry := registration.Entry{
		ID:            "stress-entry-1",
		TenantID:      "tenant-stress",
		EnvironmentID: "test",
		TrustDomain:   td,
		WorkloadID:    spiffeid.RequireFromString("spiffe://stress.example.com/workload"),
		ParentAgentID: spiffeid.RequireFromString("spiffe://stress.example.com/agent"),
		Selectors:     selectors,
		Status:        registration.StatusActive,
	}

	// Create the initial entry
	rev, err := repo.Put(context.Background(), entry, nil)
	if err != nil {
		t.Fatalf("initial put: %v", err)
	}

	// Launch concurrent writers trying to update with the same revision
	const numWriters = 10
	var wg sync.WaitGroup
	successes := make(chan int, numWriters)
	failures := make(chan int, numWriters)

	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			_, err := repo.SetStatus(context.Background(), entry.ID, registration.StatusSuspended, rev)
			if err != nil {
				failures <- writerID
			} else {
				successes <- writerID
			}
		}(i)
	}
	wg.Wait()
	close(successes)
	close(failures)

	successCount := 0
	for range successes {
		successCount++
	}
	failureCount := 0
	for range failures {
		failureCount++
    }

	// Exactly one writer should succeed with optimistic locking
	if successCount != 1 {
		t.Fatalf("expected exactly 1 success with optimistic locking, got %d successes and %d failures", successCount, failureCount)
	}
	t.Logf("concurrent writer test passed: %d success, %d conflicts", successCount, failureCount)
}

func TestMigrationChecksumVerification(t *testing.T) {
	pool := testPool(t)
	// Apply migrations twice - second time should be a no-op
	if err := store.ApplyMigrations(context.Background(), pool); err != nil {
		t.Fatalf("second migration apply should be idempotent: %v", err)
	}
}

func TestConnectionPoolExhaustion(t *testing.T) {
	dsn := os.Getenv("QREDIN_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("QREDIN_TEST_POSTGRES_DSN not set")
	}
	// Create a pool with only 2 max connections
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	checker := store.NewHealthChecker(pool)
	if err := checker.Check(context.Background()); err != nil {
		t.Fatalf("health check should pass with available connections: %v", err)
	}

	stats := checker.Stats()
	if stats.MaxConns != 2 {
		t.Fatalf("expected max_conns=2, got %d", stats.MaxConns)
	}
}
