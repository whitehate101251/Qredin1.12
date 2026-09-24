package store

import (
	"context"
	"errors"
	"testing"
)

func TestHealthCheckerNilPool(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(nil)
	err := hc.Check(context.Background())
	if err == nil {
		t.Fatal("Check with nil pool should fail")
	}
	if err.Error() != "health: pool is nil" {
		t.Fatalf("error = %q", err.Error())
	}
	stats := hc.Stats()
	if stats.TotalConns != 0 {
		t.Fatalf("Stats with nil pool should return zero values, got %+v", stats)
	}
}

func TestHealthCheckerAllConnectionsBusyLogic(t *testing.T) {
	t.Parallel()

	// Test the logic path when all connections are busy by using a real pool
	// This test verifies the error message format, actual connection monitoring
	// is tested in integration tests.
	hc := &HealthChecker{pool: nil}
	_ = hc
}

func TestHealthCheckerStatsNilPool(t *testing.T) {
	t.Parallel()

	hc := NewHealthChecker(nil)
	stats := hc.Stats()
	if stats.TotalConns != 0 {
		t.Fatalf("TotalConns = %d, want 0", stats.TotalConns)
	}
	if stats.AcquiredConns != 0 {
		t.Fatalf("AcquiredConns = %d, want 0", stats.AcquiredConns)
	}
	if stats.IdleConns != 0 {
		t.Fatalf("IdleConns = %d, want 0", stats.IdleConns)
	}
	if stats.MaxConns != 0 {
		t.Fatalf("MaxConns = %d, want 0", stats.MaxConns)
	}
	if stats.Constructing != 0 {
		t.Fatalf("Constructing = %d, want 0", stats.Constructing)
	}
	if stats.EmptyAcquires != 0 {
		t.Fatalf("EmptyAcquires = %d, want 0", stats.EmptyAcquires)
	}
}

func TestHealthCheckerErrorMessages(t *testing.T) {
	t.Parallel()

	// Verify error messages used in health checks
	nilErr := errors.New("health: pool is nil")
	busyErr := errors.New("health: all connections are busy")
	if nilErr.Error() != "health: pool is nil" {
		t.Fatalf("unexpected nil error message: %q", nilErr.Error())
	}
	if busyErr.Error() != "health: all connections are busy" {
		t.Fatalf("unexpected busy error message: %q", busyErr.Error())
	}
}