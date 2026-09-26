package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// HealthChecker provides database health checks and pool statistics.
type HealthChecker struct {
	pool *pgxpool.Pool
}

// NewHealthChecker creates a health checker for the given pool.
func NewHealthChecker(pool *pgxpool.Pool) *HealthChecker {
	return &HealthChecker{pool: pool}
}

// Check performs a basic liveness and readiness check. It pings the
// database and verifies that the pool is not exhausted.
func (h *HealthChecker) Check(ctx context.Context) error {
	if h.pool == nil {
		return errors.New("health: pool is nil")
	}
	// Ping the database to verify liveness
	if err := h.pool.Ping(ctx); err != nil {
		return err
	}
	// Verify pool is not exhausted (all connections busy)
	stat := h.pool.Stat()
	if stat.TotalConns() == stat.AcquiredConns() && stat.TotalConns() > 0 {
		return errors.New("health: all connections are busy")
	}
	return nil
}

// Stats returns detailed pool statistics for observability.
func (h *HealthChecker) Stats() HealthStats {
	if h.pool == nil {
		return HealthStats{}
	}
	stat := h.pool.Stat()
	return HealthStats{
		TotalConns:    int(stat.TotalConns()),
		AcquiredConns: int(stat.AcquiredConns()),
		IdleConns:     int(stat.IdleConns()),
		MaxConns:      int(stat.MaxConns()),
		Constructing:  int(stat.ConstructingConns()),
		EmptyAcquires: stat.EmptyAcquireCount(),
	}
}

// HealthStats holds pool statistics for monitoring and alerting.
type HealthStats struct {
	TotalConns    int
	AcquiredConns int
	IdleConns     int
	MaxConns      int
	Constructing  int
	EmptyAcquires int64
}

// RecoveryMetrics tracks backup and restore timing for RPO/RTO objectives.
type RecoveryMetrics struct {
	LastBackupTime  time.Time
	LastRestoreTime time.Time
	LastBackupSize  int64
	BackupDuration  time.Duration
	RestoreDuration time.Duration
}

// UpdateBackup records a completed backup operation.
func (m *RecoveryMetrics) UpdateBackup(size int64, duration time.Duration) {
	now := time.Now().UTC()
	m.LastBackupTime = now
	m.LastBackupSize = size
	m.BackupDuration = duration
}

// UpdateRestore records a completed restore operation.
func (m *RecoveryMetrics) UpdateRestore(duration time.Duration) {
	m.LastRestoreTime = time.Now().UTC()
	m.RestoreDuration = duration
}

// RPO returns the time since the last successful backup.
// If no backup has been recorded, it returns the maximum duration.
func (m *RecoveryMetrics) RPO() time.Duration {
	if m.LastBackupTime.IsZero() {
		return time.Duration(^uint64(0) >> 1) // max duration
	}
	return time.Since(m.LastBackupTime)
}

// RTO returns the duration of the last restore operation.
// If no restore has been recorded, it returns zero.
func (m *RecoveryMetrics) RTO() time.Duration {
	return m.RestoreDuration
}

// MeetsRPO checks if the current RPO is within the target.
func (m *RecoveryMetrics) MeetsRPO(target time.Duration) bool {
	return m.RPO() <= target
}

// MeetsRTO checks if the last restore duration is within the target.
func (m *RecoveryMetrics) MeetsRTO(target time.Duration) bool {
	return m.RTO() <= target
}
